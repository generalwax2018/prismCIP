import hashlib
import io
import json
import zipfile

from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app import chain
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, Organization


def _org():
    with SessionLocal() as db:
        return db.query(Organization).order_by(Organization.id).first().id


def test_chain_is_intact_and_continuous():
    with SessionLocal() as db:
        rep = chain.verify(db, _org())
        assert rep["ok"], rep["breaks"]
        seqs = [e.seq for e in db.query(AuditLog).filter_by(org_id=_org()).order_by(AuditLog.seq).all()]
        assert seqs == list(range(1, len(seqs) + 1))


def test_edit_is_detected_and_named():
    with SessionLocal() as db:
        e = db.query(AuditLog).filter_by(org_id=_org()).order_by(AuditLog.seq).offset(3).first()
        original, eid = e.detail, e.id
        e.detail = (e.detail or "") + " (quietly edited)"
        db.commit()
        rep = chain.verify(db, _org())
        assert not rep["ok"] and any(f"#{eid}" in b and "changed" in b for b in rep["breaks"])
        e = db.get(AuditLog, eid)
        e.detail = original
        db.commit()
        assert chain.verify(db, _org())["ok"]


def test_deletion_is_detected():
    with SessionLocal() as db:
        e = db.query(AuditLog).filter_by(org_id=_org()).order_by(AuditLog.seq).offset(5).first()
        snapshot = {c: getattr(e, c) for c in ("id", "org_id", "at", "actor", "action", "detail", "seq", "prev_hash",
                                                "hash", "sealed_at")}
        db.delete(e)
        db.commit()
        rep = chain.verify(db, _org())
        assert not rep["ok"] and any("missing" in b for b in rep["breaks"])
        db.add(AuditLog(**snapshot))
        db.commit()
        assert chain.verify(db, _org())["ok"]


def test_full_rewrite_is_caught_by_anchors():
    chain.anchor_all()
    with SessionLocal() as db:
        rows = db.query(AuditLog).filter_by(org_id=_org()).order_by(AuditLog.seq).all()
        saved = [(r.id, r.detail, r.prev_hash, r.hash) for r in rows]
        # an attacker edits an old entry and recomputes every hash after it
        rows[2].detail = "rewritten history"
        prev = rows[1].hash
        for r in rows[2:]:
            r.prev_hash = prev
            r.hash = chain.entry_hash(prev, r)
            prev = r.hash
        db.commit()
        rep = chain.verify(db, _org())
        assert not rep["ok"] and any("anchor" in b for b in rep["breaks"])
        for rid, detail, ph, h in saved:  # put it back
            r = db.get(AuditLog, rid)
            r.detail, r.prev_hash, r.hash = detail, ph, h
        db.commit()
        assert chain.verify(db, _org())["ok"]


def test_audit_package_lets_anyone_recompute_the_chain():
    with TestClient(app) as c:
        c.post("/login", data=dict(csrf=CSRF.search(c.get("/login").text).group(1), email="admin@coop.test",
                                   password="correct-horse-battery"))
        assert "Chain verified" in c.get("/activity").text
        z = zipfile.ZipFile(io.BytesIO(c.get("/export").content))
        assert "Verified: OK" in z.read("10_activity_log_verification.txt").decode()
        import csv
        rows = list(csv.DictReader(io.StringIO(z.read("06_activity_log.csv").decode())))
        org = _org()
        prev = "0" * 64
        for r in rows:  # independent recomputation, exactly as the verification note describes
            body = json.dumps([prev, int(r["seq"]), org, r["at_utc"], r["actor"], r["action"], r["detail"]],
                              ensure_ascii=False, separators=(",", ":"))
            assert r["prev_hash"] == prev
            assert hashlib.sha256(body.encode()).hexdigest() == r["hash"]
            prev = r["hash"]
        assert rows and prev == rows[-1]["hash"]
