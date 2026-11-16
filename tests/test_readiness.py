import re

from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app.db import SessionLocal
from app.main import app
from app.models import Asset, AuditLog, ReadinessItem


def _csrf(c, url="/"):
    return CSRF.search(c.get(url).text).group(1)


def test_readiness_checklist_hints_save_export_board():
    with TestClient(app) as c:
        c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="admin@coop.test", password="correct-horse-battery"))
        page = c.get("/readiness").text
        assert "CIP-003-11 readiness" in page and "Identify Shared Cyber Infrastructure" in page
        with SessionLocal() as db:
            a = db.query(Asset).filter_by(name="North Substation").first()
            aid, routable = a.id, a.routable_external
        assert routable and f'id="a{aid}"' in page
        assert "3.1.2 Detect malicious communications" in page
        before = re.search(r"In place</div><div class=\"num\">(\d+) / (\d+)", page)
        r = c.post("/readiness", data={"csrf": _csrf(c, "/readiness"), "asset_id": str(aid),
                                       "status_3.1.1": "In place", "method_3.1.1": "FortiGate policy set, reviewed",
                                       "status_3.1.2": "Planned", "owner_3.1.2": "Pat Ops",
                                       "target_3.1.2": "2020-01-01", "status_3.1.3": "Bogus"})
        assert "Saved 2 change(s)" in r.text
        after = re.search(r"In place</div><div class=\"num\">(\d+) / (\d+)", r.text)
        assert int(after.group(1)) == int(before.group(1)) + 1
        assert re.search(r"Past target date</div><div class=\"num\">1<", r.text)
        # saving again with the same values changes nothing
        r = c.post("/readiness", data={"csrf": _csrf(c, "/readiness"), "asset_id": str(aid),
                                       "status_3.1.1": "In place", "method_3.1.1": "FortiGate policy set, reviewed",
                                       "status_3.1.2": "Planned", "owner_3.1.2": "Pat Ops", "target_3.1.2": "2020-01-01"})
        assert "No changes" in r.text
        c.post("/readiness", data={"csrf": _csrf(c, "/readiness"), "status_sci": "Not applicable"})
        csv = c.get("/readiness.csv").text
        assert "FortiGate policy set, reviewed" in csv and "Organization,Scope,Identify Shared" in csv
        assert "CIP-003-11 (effective 2029-07-01)" in c.get("/reports/board").text
        with SessionLocal() as db:
            assert db.query(ReadinessItem).filter_by(asset_id=aid).count() == 2
            assert db.query(AuditLog).filter_by(action="readiness_updated").count() >= 2
    from app.auth import hash_password
    from app.models import User
    with SessionLocal() as db:
        db.add(User(org_id=a_org(db), email="ready-viewer@coop.test", name="RV", role="viewer",
                    password_hash=hash_password("harbor-lantern-quartz")))
        db.commit()
    with TestClient(app) as c:  # viewers can look but not change
        c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="ready-viewer@coop.test",
                                   password="harbor-lantern-quartz"))
        assert c.get("/readiness").status_code == 200
        assert c.post("/readiness", data={"csrf": _csrf(c, "/readiness"), "status_sci": "In place"}).status_code == 403


def a_org(db):
    return db.query(Asset).filter_by(name="North Substation").first().org_id
