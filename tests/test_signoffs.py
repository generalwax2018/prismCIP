import io
import re
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app import reminders
from app.auth import hash_password
from app.db import DATA_DIR, SessionLocal
from app.main import app
from app.models import Evidence, Organization, ReminderLog, Requirement, Signoff, User

PW = "correct-horse-battery"


def login(c, email, pw=PW):
    c.post("/login", data=dict(csrf=CSRF.search(c.get("/login").text).group(1), email=email, password=pw))


def post(c, url, data=None, files=None, page="/"):
    data = dict(data or {})
    data["csrf"] = CSRF.search(c.get(page).text).group(1)
    return c.post(url, data=data, files=files, follow_redirects=False)


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as c:
        if "/setup" in str(c.get("/login").url):
            c.post("/setup", data=dict(csrf=CSRF.search(c.get("/setup").text).group(1), org_name="Sign Co-op",
                                       name="Admin", email="admin@coop.test", password=PW))
        else:
            login(c, "admin@coop.test")
        with SessionLocal() as db:
            admin = db.query(User).filter_by(email="admin@coop.test").first()
            if not db.query(User).filter_by(email="csm@coop.test").first():
                db.add(User(org_id=admin.org_id, email="csm@coop.test", name="Dana Ortiz", role="viewer",
                            password_hash=hash_password(PW)))
                db.commit()
            csm_id = db.query(User).filter_by(email="csm@coop.test").first().id
        yield c, csm_id


def test_signer_flag_and_request(ctx):
    c, csm_id = ctx
    r = post(c, "/signoffs", dict(kind="asset_review", signer_id=csm_id), page="/signoffs")
    assert "Pick a signer" in c.get("/signoffs").text  # not a signer yet
    post(c, f"/settings/users/{csm_id}/signer", page="/settings")
    r = post(c, "/signoffs", dict(kind="asset_review", signer_id=csm_id), page="/signoffs")
    assert r.status_code == 303 and "/signoffs/" in r.headers["location"]
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    with SessionLocal() as db:
        so = db.get(Signoff, sid)
        assert so.sha256 and so.status == "Pending" and so.requirement.code == "CIP-002 R2"
    # requester (not the signer) can't decide
    r = post(c, f"/signoffs/{sid}/decide", dict(decision="approve", password=PW, signature_name="Admin"),
             page=f"/signoffs/{sid}")
    assert r.status_code == 403


def test_signer_approves_with_password_and_name(ctx):
    _c, csm_id = ctx
    with SessionLocal() as db:
        sid = db.query(Signoff).filter_by(status="Pending", kind="asset_review").first().id
    with TestClient(app) as d:
        login(d, "csm@coop.test")
        assert "Waiting for you" in d.get("/signoffs").text
        post(d, f"/signoffs/{sid}/decide", dict(decision="approve", password="wrong", signature_name="Dana Ortiz"),
             page=f"/signoffs/{sid}")
        post(d, f"/signoffs/{sid}/decide", dict(decision="approve", password=PW, signature_name="Someone Else"),
             page=f"/signoffs/{sid}")
        with SessionLocal() as db:
            assert db.get(Signoff, sid).status == "Pending"
        post(d, f"/signoffs/{sid}/decide", dict(decision="approve", password=PW, signature_name="dana ortiz"),
             page=f"/signoffs/{sid}")
    with SessionLocal() as db:
        so = db.get(Signoff, sid)
        assert so.status == "Approved" and so.evidence_id
        ev = db.get(Evidence, so.evidence_id)
        assert ev.requirement.code == "CIP-002 R2" and ev.performed_on == so.decided_at.date() and so.sha256 in ev.description


def test_tampered_document_cannot_be_signed(ctx):
    c, csm_id = ctx
    r = post(c, "/signoffs", dict(kind="policy", signer_id=csm_id),
             files={"file": ("policy.pdf", io.BytesIO(b"%PDF policy v5"), "application/pdf")}, page="/signoffs")
    sid = int(r.headers["location"].rsplit("/", 1)[1])
    with SessionLocal() as db:
        so = db.get(Signoff, sid)
        (DATA_DIR / "evidence" / str(so.org_id) / "signoffs" / so.stored_name).write_bytes(b"%PDF changed")
    with TestClient(app) as d:
        login(d, "csm@coop.test")
        assert "Changed or missing" in d.get(f"/signoffs/{sid}").text
        post(d, f"/signoffs/{sid}/decide", dict(decision="approve", password=PW, signature_name="Dana Ortiz"),
             page=f"/signoffs/{sid}")
    with SessionLocal() as db:
        assert db.get(Signoff, sid).status == "Pending"


def test_reminders_fire_once_per_milestone(ctx):
    with SessionLocal() as db:
        org = db.query(Organization).order_by(Organization.id).first()
        req = db.query(Requirement).filter_by(code="CIP-003 Att1 S1").first()
        db.query(ReminderLog).delete()
        db.commit()
        from app.compliance import requirement_statuses
        due = next(x.due for x in requirement_statuses(db, org) if x.req.code == "CIP-003 Att1 S1")
        today = due - timedelta(days=20)
        items = reminders.pending(db, org, today)
        s1 = [i for i in items if i.key.startswith("req:CIP-003 Att1 S1:")]
        assert s1 and s1[0].key.endswith(":30")
        r1 = reminders.send_due(db, org, today)
        assert r1["sent"] >= 1 and r1["messages"] >= 1
        assert not [i for i in reminders.pending(db, org, today) if i.key.startswith("req:CIP-003 Att1 S1:")]
        later = [i for i in reminders.pending(db, org, today + timedelta(days=15)) if "Att1 S1:" in i.key]
        assert later and later[0].key.endswith(":7")
    outbox = list((DATA_DIR / "outbox").glob("*.eml"))
    assert any("compliance item" in m.read_text(errors="replace") for m in outbox)
