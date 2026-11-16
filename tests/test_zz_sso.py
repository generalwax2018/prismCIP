"""Single sign-on against a fake identity provider (discovery, JWKS, token endpoint) on a loopback port."""
import base64
import hashlib
import json
import random
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app import oidc
from app.auth import hash_password
from app.db import SessionLocal
from app.main import app
from app.models import AuditLog, Organization, User

PW = "harbor-lantern-quartz"
ADMIN = ("admin@coop.test", "correct-horse-battery")


# ---------------------------------------------------------------- tiny RSA (test only)
def _prime(bits, rng):
    while True:
        p = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(p % q for q in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)) and _mr(p, rng):
            return p


def _mr(n, rng, rounds=24):
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _keypair():
    rng, e = random.Random(4242), 65537
    while True:
        p, q = _prime(1024, rng), _prime(1024, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


N, E, D = _keypair()
_DI = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int_b64(i):
    return _b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))


def sign_jwt(claims, kid="k1", d=D):
    h = _b64(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
    p = _b64(json.dumps(claims).encode())
    k = (N.bit_length() + 7) // 8
    t = _DI + hashlib.sha256(f"{h}.{p}".encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), d, N).to_bytes(k, "big")
    return f"{h}.{p}.{_b64(sig)}"


# ---------------------------------------------------------------- fake IdP
class IdP:
    codes: dict = {}   # code -> (claims, challenge)
    seen: list = []


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        if self.path == "/.well-known/openid-configuration":
            return self._json({"issuer": base, "authorization_endpoint": base + "/authorize",
                               "token_endpoint": base + "/token", "jwks_uri": base + "/jwks"})
        if self.path == "/jwks":
            return self._json({"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "n": _int_b64(N),
                                         "e": _int_b64(E)}]})
        self._json({"error": "not_found"}, 404)

    def do_POST(self):
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        IdP.seen.append(dict(form, auth=self.headers.get("Authorization", "")))
        entry = IdP.codes.pop(form.get("code", ""), None)
        if not entry:
            return self._json({"error": "invalid_grant"}, 400)
        claims, challenge = entry
        verifier_ok = _b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) == challenge
        if not verifier_ok:
            return self._json({"error": "invalid_grant", "error_description": "PKCE"}, 400)
        self._json({"id_token": sign_jwt(claims), "token_type": "Bearer"})


@pytest.fixture(scope="module")
def idp():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    oidc._cache.clear()


def _csrf(c, url="/"):
    return CSRF.search(c.get(url).text).group(1)


def _login(c, email, pw):
    return c.post("/login", data=dict(csrf=_csrf(c, "/login"), email=email, password=pw), follow_redirects=False)


def _sso(c, issuer, email, claim_email=None, **over):
    """Run the browser side: start at /login/sso, 'sign in' at the IdP, come back with a code."""
    r = c.post("/login/sso", data=dict(csrf=_csrf(c, "/login/sso"), email=email), follow_redirects=False)
    assert r.status_code == 303, r.text
    auth = urlparse(r.headers["location"])
    assert auth.path == "/authorize" and r.headers["location"].startswith(issuer)
    q = {k: v[0] for k, v in parse_qs(auth.query).items()}
    assert q["code_challenge_method"] == "S256" and q["login_hint"] == email
    claims = {"iss": issuer, "aud": q["client_id"], "sub": "u-" + email, "email": claim_email or email,
              "email_verified": True, "nonce": q["nonce"], "iat": int(time.time()), "exp": int(time.time()) + 300}
    claims.update(over)
    code = "c" + str(random.random())[2:]
    IdP.codes[code] = (claims, q["code_challenge"])
    return c.get("/login/sso/callback", params={"code": code, "state": q["state"]}, follow_redirects=False)


def test_rs256_helper_matches_verifier():
    tok = sign_jwt({"a": 1})
    h, p, s = tok.split(".")
    assert oidc.rs256_verify(N, E, f"{h}.{p}".encode(), oidc.b64url_decode(s))
    assert not oidc.rs256_verify(N, E, f"{h}.{p}x".encode(), oidc.b64url_decode(s))


def test_sso_setup_sign_in_refusals_and_required(idp):
    with SessionLocal() as db:
        home = db.query(Organization).order_by(Organization.id).first()
        db.add(User(org_id=home.id, email="lineman@coop.test", name="Lee Lineman", role="viewer",
                    password_hash=hash_password(PW), must_change_password=False))
        db.commit()
    with TestClient(app) as c:
        assert "single sign-on" not in c.get("/login").text
        _login(c, *ADMIN)
        # https is required except on loopback
        r = c.post("/settings/sso", data=dict(csrf=_csrf(c, "/settings"), oidc_issuer="http://idp.example",
                                              oidc_client_id="prismcip", oidc_domain="coop.test"))
        assert "must start with https://" in r.text
        r = c.post("/settings/sso", data=dict(csrf=_csrf(c, "/settings"), oidc_issuer=idp, oidc_client_id="prismcip",
                                          oidc_client_secret="s3cret", oidc_domain="@Coop.test"))
        assert "identity provider answered" in r.text
        with SessionLocal() as db:
            org = db.query(Organization).order_by(Organization.id).first()
            assert org.oidc_domain == "coop.test" and org.oidc_client_secret and "s3cret" not in org.oidc_client_secret

    with TestClient(app) as c:
        assert "single sign-on" in c.get("/login").text
        r = _sso(c, idp, "lineman@coop.test")
        assert r.status_code == 303 and r.headers["location"] == "/"
        assert "Lee Lineman" in c.get("/").text
        assert IdP.seen[-1]["auth"].startswith("Basic ")  # client secret sent, sealed at rest

    with TestClient(app) as c:  # the IdP vouches for someone outside the claimed domain
        r = _sso(c, idp, "lineman@coop.test", claim_email="consultant@gt.test")
        assert "sign in through this utility" in r.text
        assert c.get("/", follow_redirects=False).status_code in (302, 303)
    with TestClient(app) as c:  # replayed/forged state
        c.post("/login/sso", data=dict(csrf=_csrf(c, "/login/sso"), email="lineman@coop.test"))
        r = c.get("/login/sso/callback", params={"code": "x", "state": "forged"})
        assert "expired or was started somewhere else" in r.text
    with TestClient(app) as c:  # wrong nonce / audience
        assert "different application" in _sso(c, idp, "lineman@coop.test", aud="someone-else").text
    with TestClient(app) as c:
        assert "set up for that email" in c.post(
            "/login/sso", data=dict(csrf=_csrf(c, "/login/sso"), email="who@else.test")).text

    with TestClient(app) as c:  # require SSO: password sign-in stops for people who only work here
        _login(c, *ADMIN)
        c.post("/settings/sso", data=dict(csrf=_csrf(c, "/settings"), oidc_issuer=idp, oidc_client_id="prismcip",
                                          oidc_domain="coop.test", sso_required="on"))
    with TestClient(app) as c:
        r = _login(c, "lineman@coop.test", PW)
        assert "requires single sign-on" in r.text
        assert _sso(c, idp, "lineman@coop.test").status_code == 303
    with SessionLocal() as db:
        acts = {a.action for a in db.query(AuditLog).all()}
        assert {"sso_configured", "sso_refused"} <= acts

    with TestClient(app) as c:  # tidy up for anything after this module
        _login(c, *ADMIN)
        c.post("/settings/sso", data=dict(csrf=_csrf(c, "/settings"), action="remove"))
    with SessionLocal() as db:
        assert not db.query(Organization).filter(Organization.oidc_issuer.isnot(None)).count()
