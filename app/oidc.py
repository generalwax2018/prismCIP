"""Single sign-on with OpenID Connect (Microsoft Entra ID, Okta, Google Workspace, Ping, Auth0, ...).

Ported from RiskPrism's implementation. Two ways to configure it:
  * per utility, in Settings -> Single sign-on (issuer, client ID, client secret, email domain), for hosted or
    co-op installs where each utility brings its own identity provider; or
  * install-wide with PRISMCIP_OIDC_ISSUER, PRISMCIP_OIDC_CLIENT_ID, PRISMCIP_OIDC_CLIENT_SECRET.

People still need a PrismCIP account (or membership) with the same email; SSO replaces the password and the
authenticator-app step. Register <base URL>/login/sso/callback as the redirect URI.

Authorization code flow with PKCE (S256), state and nonce, kept in the signed session cookie. The ID token's
RS256 signature is checked against the provider's published keys with plain integer arithmetic (no crypto
library), then issuer, audience, expiry, issued-at and nonce. Only https issuers (loopback http for tests).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlparse

FLOW_SECONDS = 600
SKEW = 120
TIMEOUT = 15
LOOPBACK = ("127.0.0.1", "localhost", "::1")
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


class OIDCError(RuntimeError):
    pass


def env_settings() -> dict | None:
    e = os.environ
    issuer, cid = (e.get("PRISMCIP_OIDC_ISSUER") or "").strip().rstrip("/"), (e.get("PRISMCIP_OIDC_CLIENT_ID") or "").strip()
    if not (issuer and cid):
        return None
    return {"issuer": issuer, "client_id": cid, "client_secret": e.get("PRISMCIP_OIDC_CLIENT_SECRET") or "",
            "email_claim": (e.get("PRISMCIP_OIDC_EMAIL_CLAIM") or "").strip(), "org_id": None}


def org_settings(org) -> dict | None:
    if not (org.oidc_issuer and org.oidc_client_id):
        return None
    from .totp import unseal
    return {"issuer": org.oidc_issuer.strip().rstrip("/"), "client_id": org.oidc_client_id.strip(),
            "client_secret": (unseal(org.oidc_client_secret) or "") if org.oidc_client_secret else "",
            "email_claim": "", "org_id": org.id}


def find_settings(db, email: str) -> dict | None:
    """The identity provider for this person: their utility's (by membership or email domain), else install-wide."""
    from .members import orgs_for
    from .models import Organization, User
    email = (email or "").strip().lower()
    u = db.query(User).filter_by(email=email).first() if email else None
    if u:
        for org, _m in orgs_for(db, u):
            cfg = org_settings(org)
            if cfg:
                return cfg
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    if domain:
        for org in db.query(Organization).filter(Organization.oidc_domain.isnot(None)).all():
            if domain in [d.strip().lower() for d in (org.oidc_domain or "").split(",")]:
                cfg = org_settings(org)
                if cfg:
                    return cfg
    return env_settings()


def any_configured(db) -> bool:
    from .models import Organization
    return bool(env_settings()) or db.query(Organization).filter(Organization.oidc_issuer.isnot(None)).count() > 0


# ------------------------------------------------------------------ helpers
def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _check_url(url: str) -> None:
    u = urlparse(url)
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname in LOOPBACK:
        return
    raise OIDCError("The identity provider address must start with https:// (got %s)." % url[:80])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OIDCError("The identity provider redirected a back-channel request (HTTP %d)." % code)


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch_json(url: str, data: dict | None = None, auth: tuple[str, str] | None = None) -> dict:
    _check_url(url)
    headers = {"Accept": "application/json", "User-Agent": "PrismCIP"}
    body = None
    if data is not None:
        body = urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if auth:
        from urllib.parse import quote
        headers["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (quote(auth[0], safe=""), quote(auth[1], safe=""))).encode()).decode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as resp:
            out = json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = e.read(300).decode("utf-8", "replace")
        raise OIDCError("The identity provider refused the request (HTTP %d): %s" % (e.code, detail[:160]))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise OIDCError("Could not reach the identity provider: %s" % str(getattr(e, "reason", e))[:120])
    except ValueError:
        raise OIDCError("The identity provider sent back something that is not JSON.")
    if not isinstance(out, dict):
        raise OIDCError("The identity provider sent back an unexpected reply.")
    return out


def _cached(key: str, ttl: float, load):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    val = load()
    with _lock:
        _cache[key] = (time.time(), val)
    return val


def discovery(s: dict) -> dict:
    meta = _cached("disc|" + s["issuer"], 3600, lambda: _fetch_json(s["issuer"] + "/.well-known/openid-configuration"))
    if meta.get("issuer", "").rstrip("/") != s["issuer"]:
        raise OIDCError("The identity provider's discovery document names a different issuer.")
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not meta.get(k):
            raise OIDCError("The identity provider's discovery document has no %s." % k)
        _check_url(meta[k])
    return meta


def _jwks(s: dict, force: bool = False) -> list[dict]:
    uri = discovery(s)["jwks_uri"]
    key = "jwks|" + uri
    if force:
        with _lock:
            hit = _cache.get(key)
            if hit and time.time() - hit[0] < 60:  # refetch at most once a minute
                return hit[1].get("keys") or []
            _cache.pop(key, None)
    return _cached(key, 3600, lambda: _fetch_json(uri)).get("keys") or []


# ------------------------------------------------------------------ RS256
def rs256_verify(n: int, e: int, signing_input: bytes, sig: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256, by the book (RFC 8017 8.2.2), comparing the whole encoded block."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k or k < 256:  # at least 2048-bit keys
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def verify_id_token(s: dict, token: str, nonce: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    try:
        h64, p64, s64 = token.split(".")
        header = json.loads(b64url_decode(h64))
        claims = json.loads(b64url_decode(p64))
        sig = b64url_decode(s64)
    except (ValueError, TypeError):
        raise OIDCError("The identity provider sent an unreadable ID token.")
    if header.get("alg") != "RS256":
        raise OIDCError("Only RS256-signed ID tokens are accepted (got %s)." % str(header.get("alg"))[:20])
    kid = header.get("kid")

    def pick(keys):
        return [k for k in keys if k.get("kty") == "RSA" and k.get("use", "sig") == "sig" and (kid is None or k.get("kid") == kid)]
    keys = pick(_jwks(s)) or pick(_jwks(s, force=True))
    signing_input = (h64 + "." + p64).encode("ascii")
    ok = False
    for k in keys:
        try:
            n = int.from_bytes(b64url_decode(k["n"]), "big")
            e = int.from_bytes(b64url_decode(k["e"]), "big")
        except (KeyError, ValueError, TypeError):
            continue
        if rs256_verify(n, e, signing_input, sig):
            ok = True
            break
    if not ok:
        raise OIDCError("The ID token's signature does not match the identity provider's keys.")
    if str(claims.get("iss", "")).rstrip("/") != s["issuer"]:
        raise OIDCError("The ID token was issued by someone else.")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if s["client_id"] not in auds or (len(auds) > 1 and claims.get("azp") not in (None, s["client_id"])):
        raise OIDCError("The ID token was issued for a different application.")
    try:
        exp, iat = float(claims["exp"]), float(claims.get("iat", now))
    except (KeyError, TypeError, ValueError):
        raise OIDCError("The ID token has no expiry.")
    if exp + SKEW < now or iat - SKEW > now:
        raise OIDCError("The ID token has expired or is not valid yet. Check the server clock.")
    if not nonce or not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OIDCError("The ID token does not belong to this sign-in attempt.")
    return claims


def email_of(s: dict, claims: dict) -> str:
    order = [s["email_claim"]] if s["email_claim"] else ["email", "preferred_username", "upn"]
    if claims.get("email_verified") is False and "email" in order:
        order.remove("email")
    for c in order:
        v = str(claims.get(c) or "").strip().lower()
        if "@" in v:
            return v[:200]
    raise OIDCError("The identity provider did not say which email address you signed in with.")


# ------------------------------------------------------------------ the flow
def begin(s: dict, redirect_uri: str, email_hint: str = "") -> tuple[str, dict]:
    """(authorization URL, flow data to keep in the signed session)."""
    meta = discovery(s)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    params = {"response_type": "code", "client_id": s["client_id"], "redirect_uri": redirect_uri,
              "scope": "openid email profile", "state": state, "nonce": nonce, "code_challenge": challenge,
              "code_challenge_method": "S256", "prompt": "select_account"}
    if email_hint:
        params["login_hint"] = email_hint
    url = meta["authorization_endpoint"] + ("&" if "?" in meta["authorization_endpoint"] else "?") + urlencode(params)
    flow = {"state": state, "nonce": nonce, "verifier": verifier, "exp": int(time.time()) + FLOW_SECONDS,
            "org_id": s.get("org_id")}
    return url, flow


def finish(s: dict, flow: dict | None, query: dict, redirect_uri: str) -> str:
    """Exchange the code and return the verified email address."""
    if query.get("error"):
        raise OIDCError("The identity provider did not sign you in: %s" %
                        str(query.get("error_description") or query["error"])[:160])
    if not flow or flow.get("exp", 0) < time.time() or not query.get("state") or \
            not hmac.compare_digest(flow["state"], str(query["state"])):
        raise OIDCError("This sign-in attempt expired or was started somewhere else. Try again.")
    code = str(query.get("code") or "")
    if not code:
        raise OIDCError("The identity provider sent no authorization code.")
    meta = discovery(s)
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "code_verifier": flow["verifier"], "client_id": s["client_id"]}
    methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    auth = None
    if s["client_secret"]:
        if "client_secret_post" in methods and "client_secret_basic" not in methods:
            data["client_secret"] = s["client_secret"]
        else:
            auth = (s["client_id"], s["client_secret"])
    tok = _fetch_json(meta["token_endpoint"], data, auth)
    if not tok.get("id_token"):
        raise OIDCError("The identity provider returned no ID token.")
    return email_of(s, verify_id_token(s, str(tok["id_token"]), flow["nonce"]))
