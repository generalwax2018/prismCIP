import re

from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app.auth import hash_password
from app.db import SessionLocal
from app.main import app
from app.models import Asset, Membership, Organization, User

PW = "harbor-lantern-quartz"


def _csrf(c, url="/"):
    return CSRF.search(c.get(url).text).group(1)


def _login(c, email, pw=PW):
    c.post("/login", data=dict(csrf=_csrf(c, "/login"), email=email, password=pw))


def test_partner_creates_utilities_and_data_stays_separate(monkeypatch):
    with SessionLocal() as db:
        home = db.query(Organization).order_by(Organization.id).first()
        db.add(User(org_id=home.id, email="consultant@gt.test", name="Casey Consultant", role="admin",
                    is_partner=True, password_hash=hash_password(PW)))
        db.commit()
    with TestClient(app) as c:
        _login(c, "consultant@gt.test")
        assert "North Substation" in c.get("/assets").text
        c.post("/orgs", data=dict(csrf=_csrf(c, "/portfolio"), name="Prairie Muni Light"))
        assert "Prairie Muni Light" in c.get("/").text and "North Substation" not in c.get("/assets").text
        c.post("/assets/new", data=dict(csrf=_csrf(c, "/assets/new"), name="Muni Sub A", asset_type="Substation"))
        page = c.get("/portfolio").text
        assert "Prairie Muni Light" in page and home.name in page
        # switch back: the new utility's asset isn't visible
        c.post("/orgs/switch", data=dict(csrf=_csrf(c), org_id=home.id))
        assets = c.get("/assets").text
        assert "North Substation" in assets and "Muni Sub A" not in assets
        # can't switch into a utility you don't belong to
        with SessionLocal() as db:
            stranger = Organization(name="Stranger Co-op")
            db.add(stranger)
            db.commit()
            sid = stranger.id
        assert c.post("/orgs/switch", data=dict(csrf=_csrf(c), org_id=sid)).status_code == 403


def test_non_partner_cannot_create_utilities():
    with TestClient(app) as c:
        _login(c, "admin@coop.test", "correct-horse-battery")
        assert c.post("/orgs", data=dict(csrf=_csrf(c, "/portfolio"), name="Nope")).status_code == 403


def test_inviting_existing_account_adds_access_and_signer_is_per_utility():
    with SessionLocal() as db:
        muni = db.query(Organization).filter_by(name="Prairie Muni Light").first()
        muni_id = muni.id
    with TestClient(app) as c:
        _login(c, "consultant@gt.test")
        c.post("/orgs/switch", data=dict(csrf=_csrf(c), org_id=muni_id))
        r = c.post("/settings/users", data=dict(csrf=_csrf(c, "/settings"), email="admin@coop.test", role="viewer",
                                                 name="x", password="unused-but-required-here"))
        with SessionLocal() as db:
            admin = db.query(User).filter_by(email="admin@coop.test").first()
            m = db.query(Membership).filter_by(user_id=admin.id, org_id=muni_id).first()
            assert m and m.role == "viewer" and admin.org_id != muni_id
            uid, home_id = admin.id, admin.org_id
            home_m = db.query(Membership).filter_by(user_id=uid, org_id=home_id).first()
            home_sign = home_m.can_sign
        c.post(f"/settings/users/{uid}/signer", data=dict(csrf=_csrf(c, "/settings")))
        with SessionLocal() as db:
            assert db.query(Membership).filter_by(user_id=uid, org_id=muni_id).first().can_sign is True
            assert db.query(Membership).filter_by(user_id=uid, org_id=home_id).first().can_sign == home_sign
        # removing them from the muni removes access there only
        c.post(f"/settings/users/{uid}/toggle", data=dict(csrf=_csrf(c, "/settings")))
        with SessionLocal() as db:
            assert not db.query(Membership).filter_by(user_id=uid, org_id=muni_id).first()
            assert db.get(User, uid).active
