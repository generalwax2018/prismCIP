import re
import time

from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app import totp
from app.auth import hash_password
from app.db import SessionLocal
from app.main import app
from app.models import Organization, User

PW = "mfa-user-password-1"


def _csrf(c, url):
    return CSRF.search(c.get(url).text).group(1)


def test_enroll_login_and_replay_block():
    with SessionLocal() as db:
        org = db.query(Organization).order_by(Organization.id).first() or Organization(name="MFA Co-op")
        if not org.id:
            db.add(org)
            db.flush()
        if not db.query(User).filter_by(email="mfa@coop.test").first():
            db.add(User(org_id=org.id, email="mfa@coop.test", name="M", role="editor", password_hash=hash_password(PW)))
        db.commit()
    with TestClient(app) as c:
        c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="mfa@coop.test", password=PW))
        page = c.get("/settings/mfa").text
        assert "<svg" in page and "otpauth" not in page  # QR drawn locally, URI not leaked as text
        secret = re.search(r'<span class="mono wrap-any">([A-Z2-7]+)</span>', page).group(1)
        c.post("/settings/mfa", data=dict(csrf=_csrf(c, "/settings/mfa"), action="enable", code="000000"))
        with SessionLocal() as db:
            assert db.query(User).filter_by(email="mfa@coop.test").first().totp_secret is None
        c.post("/settings/mfa", data=dict(csrf=_csrf(c, "/settings/mfa"), action="enable",
                                          code=totp.now_code(secret, time.time() - 30)))
        with SessionLocal() as db:
            u = db.query(User).filter_by(email="mfa@coop.test").first()
            assert u.totp_secret and secret not in u.totp_secret  # sealed at rest
    with TestClient(app) as c:
        r = c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="mfa@coop.test", password=PW),
                   follow_redirects=False)
        assert r.headers["location"] == "/login/mfa"
        assert c.get("/", follow_redirects=False).headers["location"] == "/login"  # password alone isn't enough
        c.post("/login/mfa", data=dict(csrf=_csrf(c, "/login/mfa"), code="123456"))
        used = totp.now_code(secret)
        r = c.post("/login/mfa", data=dict(csrf=_csrf(c, "/login/mfa"), code=used),
                   follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/"
        assert c.get("/").status_code == 200
    with TestClient(app) as c:  # the same code can't be used twice
        c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="mfa@coop.test", password=PW))
        c.post("/login/mfa", data=dict(csrf=_csrf(c, "/login/mfa"), code=used))
        assert c.get("/", follow_redirects=False).status_code == 303
