import re
from datetime import timedelta

from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401  (throwaway data folder)
from app.auth import hash_password, password_problem
from app.db import DATA_DIR, SessionLocal
from app.main import app
from app.models import LoginAttempt, Organization, PasswordReset, User, utcnow

PW = "granite-meadow-falcon"


def _csrf(c, url):
    return CSRF.search(c.get(url).text).group(1)


def _user(email):
    with SessionLocal() as db:
        if not db.query(User).filter_by(email=email).first():
            org = db.query(Organization).order_by(Organization.id).first()
            if not org:
                org = Organization(name="Acct Co-op")
                db.add(org)
                db.flush()
            db.add(User(org_id=org.id, email=email, name="Pat Example", role="editor",
                        password_hash=hash_password(PW)))
            db.commit()


def login(c, email, pw):
    return c.post("/login", data=dict(csrf=_csrf(c, "/login"), email=email, password=pw), follow_redirects=False)


def test_password_policy():
    assert password_problem("short")
    assert password_problem("password1234")
    assert password_problem("aaaaaaaaaaaaaa")
    assert password_problem("patexample-and-more", "patexample@x.com")
    assert password_problem("Pat Example rules 99", "p@x.com", "Pat Example")
    assert password_problem("blue harbor lantern") is None


def test_account_lockout_after_five_failures():
    _user("lock@coop.test")
    with TestClient(app) as c:
        for _ in range(5):
            assert "Wrong email or password" in login(c, "lock@coop.test", "nope-nope-nope").text
        # correct password is refused while locked, with the generic message
        r = login(c, "lock@coop.test", PW)
        assert "Too many attempts" in r.text
    with SessionLocal() as db:  # after the window passes it works again
        for a in db.query(LoginAttempt).filter_by(email="lock@coop.test").all():
            a.at = a.at - timedelta(minutes=16)
        db.commit()
    with TestClient(app) as c:
        assert login(c, "lock@coop.test", PW).headers.get("location") == "/"


def test_ip_spray_blocked():
    with TestClient(app) as c:
        for i in range(20):
            login(c, f"nobody{i}@coop.test", "whatever-whatever")
        assert "Too many attempts" in login(c, "someone-else@coop.test", "x" * 12).text
    with SessionLocal() as db:
        db.query(LoginAttempt).delete()
        db.commit()


def test_forgot_and_reset_link_single_use_and_signs_out_sessions():
    _user("reset@coop.test")
    with TestClient(app) as old:  # an existing session that must end after the reset
        login(old, "reset@coop.test", PW)
        assert old.get("/").status_code == 200
        with TestClient(app) as c:
            r = c.post("/forgot", data=dict(csrf=_csrf(c, "/forgot"), email="reset@coop.test"))
            assert "If that email has an account" in r.text
            r2 = c.post("/forgot", data=dict(csrf=_csrf(c, "/forgot"), email="ghost@coop.test"))
            assert "If that email has an account" in r2.text  # no account enumeration
            mails = sorted((DATA_DIR / "outbox").glob("*.eml"), key=lambda p: p.stat().st_mtime)
            body = next(m.read_text(errors="replace") for m in reversed(mails) if "reset@coop.test" in m.read_text(errors="replace"))
            token = re.search(r"/reset/([\w-]+)", body).group(1)
            with SessionLocal() as db:
                assert not db.query(PasswordReset).filter(PasswordReset.token_hash == token).first()  # hashed
            page = c.get(f"/reset/{token}").text
            assert "Set a new password" in page
            c.post(f"/reset/{token}", data=dict(csrf=_csrf(c, f"/reset/{token}"), new_password="short",
                                                confirm="short"))
            c.post(f"/reset/{token}", data=dict(csrf=_csrf(c, f"/reset/{token}"), new_password="river stone compass",
                                                confirm="river stone compass"))
            assert "expired or was already used" in c.get(f"/reset/{token}").text
            assert login(c, "reset@coop.test", "river stone compass").headers.get("location") == "/"
        assert old.get("/", follow_redirects=False).headers["location"] == "/login"


def test_expired_reset_link():
    _user("exp@coop.test")
    with TestClient(app) as c:
        c.post("/forgot", data=dict(csrf=_csrf(c, "/forgot"), email="exp@coop.test"))
        with SessionLocal() as db:
            r = db.query(PasswordReset).order_by(PasswordReset.id.desc()).first()
            r.expires_at = utcnow() - timedelta(minutes=1)
            db.commit()
        mails = sorted((DATA_DIR / "outbox").glob("*.eml"), key=lambda p: p.stat().st_mtime)
        body = next(m.read_text(errors="replace") for m in reversed(mails) if "exp@coop.test" in m.read_text(errors="replace"))
        token = re.search(r"/reset/([\w-]+)", body).group(1)
        assert "expired or was already used" in c.get(f"/reset/{token}").text
