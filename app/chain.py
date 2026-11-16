"""Tamper-evident activity log.

Every entry is chained per organization: hash = SHA-256(prev_hash, seq, org, time, actor, action, detail).
Changing or deleting any past entry breaks every hash after it, and verify() reports the first break.

Entries are sealed right after the transaction that wrote them commits (one sealer at a time), so the chain has
no forks. A chain alone can be rebuilt end to end by someone with full database access, so the head hash of
each organization is also written daily to an anchor file outside the database (data/chain_anchors.log). That
file is included in backups and audit packages; verify() checks that every anchored hash still matches.
"""
from __future__ import annotations

import hashlib
import json
import threading

from sqlalchemy import event
from sqlalchemy.orm import Session

from .db import DATA_DIR, SessionLocal
from .models import AuditLog, Organization, utcnow

GENESIS = "0" * 64
ANCHORS = DATA_DIR / "chain_anchors.log"
_lock = threading.Lock()


def entry_hash(prev: str, e: AuditLog) -> str:
    body = json.dumps([prev, e.seq, e.org_id, e.at.isoformat(timespec="microseconds"), e.actor, e.action,
                       e.detail or ""], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def seal_pending(db: Session | None = None) -> int:
    """Chain every unsealed entry, in id order, for every organization. Safe to call any time."""
    own = db is None
    db = db or SessionLocal()
    n = 0
    try:
        with _lock:
            if db.bind.dialect.name == "postgresql":  # one sealer across every app process
                from sqlalchemy import text
                db.execute(text("SELECT pg_advisory_xact_lock(724113)"))
            pending = db.query(AuditLog).filter(AuditLog.hash.is_(None)).order_by(AuditLog.id).all()
            heads: dict[int, tuple[int, str]] = {}
            now = utcnow()
            for e in pending:
                if e.org_id not in heads:
                    last = (db.query(AuditLog).filter(AuditLog.org_id == e.org_id, AuditLog.hash.isnot(None))
                            .order_by(AuditLog.seq.desc()).first())
                    heads[e.org_id] = (last.seq, last.hash) if last else (0, GENESIS)
                seq, prev = heads[e.org_id]
                e.seq, e.prev_hash = seq + 1, prev
                e.hash, e.sealed_at = entry_hash(prev, e), now
                heads[e.org_id] = (e.seq, e.hash)
                n += 1
            if n:
                db.info["sealing"] = True
                db.commit()
                db.info.pop("sealing", None)
    finally:
        if own:
            db.close()
    return n


def verify(db: Session, org_id: int) -> dict:
    seal_pending()
    rows = db.query(AuditLog).filter_by(org_id=org_id).order_by(AuditLog.seq).all()
    prev, expected_seq, breaks = GENESIS, 1, []
    for e in rows:
        if e.seq != expected_seq:
            breaks.append(f"entry #{e.id}: sequence {e.seq}, expected {expected_seq} (an entry is missing)")
        if e.prev_hash != prev:
            breaks.append(f"entry #{e.id} (seq {e.seq}): link to the previous entry doesn't match")
        if e.hash != entry_hash(e.prev_hash or "", e):
            breaks.append(f"entry #{e.id} (seq {e.seq}): content was changed after it was recorded")
        prev, expected_seq = e.hash, (e.seq or 0) + 1
        if len(breaks) >= 20:
            break
    by_seq = {e.seq: e.hash for e in rows}
    anchors_checked, anchor_breaks = 0, []
    for a in read_anchors(org_id):
        anchors_checked += 1
        if by_seq.get(a["seq"]) != a["hash"]:
            anchor_breaks.append(f"anchor {a['at']} (seq {a['seq']}): stored hash no longer matches the log")
    first = rows[0] if rows else None
    return {"ok": not breaks and not anchor_breaks, "entries": len(rows), "breaks": breaks + anchor_breaks,
            "head": rows[-1].hash if rows else GENESIS, "head_seq": rows[-1].seq if rows else 0,
            "anchors": anchors_checked, "first_sealed": first.sealed_at if first else None,
            "first_at": first.at if first else None}


def read_anchors(org_id: int | None = None) -> list[dict]:
    if not ANCHORS.exists():
        return []
    out = []
    for line in ANCHORS.read_text().splitlines():
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if org_id is None or a.get("org") == org_id:
            out.append(a)
    return out


def anchor_all() -> int:
    """Append each organization's current head hash to the anchor file (skipped if unchanged)."""
    seal_pending()
    n = 0
    with SessionLocal() as db:
        last = {}
        for a in read_anchors():
            last[a["org"]] = a["seq"]
        with open(ANCHORS, "a") as f:
            for org in db.query(Organization).all():
                head = (db.query(AuditLog).filter(AuditLog.org_id == org.id, AuditLog.hash.isnot(None))
                        .order_by(AuditLog.seq.desc()).first())
                if head and last.get(org.id) != head.seq:
                    f.write(json.dumps({"at": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "org": org.id,
                                        "seq": head.seq, "hash": head.hash}) + "\n")
                    n += 1
    return n


@event.listens_for(Session, "before_flush")
def _mark(session, _ctx, _instances):
    if any(isinstance(o, AuditLog) for o in session.new):
        session.info["audit_written"] = True


@event.listens_for(Session, "after_commit")
def _seal_after_commit(session):
    if session.info.pop("audit_written", False) and not session.info.get("sealing"):
        seal_pending()
