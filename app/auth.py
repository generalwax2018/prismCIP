"""Password hashing, sessions, roles and CSRF."""
import hashlib
import hmac
import secrets

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .db import get_db
from .models import AuditLog, User

ROLES = ("admin", "editor", "viewer")
_SCRYPT = dict(n=2**14, r=8, p=1, dklen=64)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    return hmac.compare_digest(digest.hex(), digest_hex)


class LoginRequired(Exception):
    pass


class PasswordChangeRequired(Exception):
    pass


# Pages a user with a temporary password may still open.
_CHANGE_ALLOWED = ("/account/password", "/logout")


def start_session(request: Request, user: User) -> None:
    request.session.clear()
    request.session["uid"], request.session["sv"] = user.id, user.session_version or 1


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("uid")
    user = db.get(User, uid) if uid else None
    if not user or not user.active or request.session.get("sv") != (user.session_version or 1):
        raise LoginRequired()
    lock = request.session.get("org_lock")
    if lock and user.org_id != lock:  # signed in through one utility's own SSO: stay in that utility
        from .members import switch
        if not switch(db, user, lock):
            raise LoginRequired()
        db.commit()
    if user.must_change_password and request.url.path not in _CHANGE_ALLOWED:
        raise PasswordChangeRequired()
    return user


COMMON = {"password1234", "123456789012", "qwertyuiopas", "welcome12345", "changeme1234", "password123!",
          "letmein12345", "administrator", "prismcip1234", "summer2026!!", "winter2026!!", "p@ssw0rd1234"}


def password_problem(password: str, email: str = "", name: str = "") -> str | None:
    """Return why a new password isn't acceptable, or None."""
    if len(password) < 12:
        return "Use at least 12 characters."
    if len(password) > 256:
        return "Use at most 256 characters."
    low = password.lower()
    if low in COMMON or len(set(low)) < 5:
        return "That password is too easy to guess."
    local = email.split("@")[0].lower()
    if (local and len(local) >= 4 and local in low) or (name and len(name) >= 4 and name.lower() in low):
        return "Don't use your name or email in your password."
    return None


def require_role(*roles):
    def dep(request: Request, user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Your role can't do that.")
        from .billing import check_write
        check_write(request, user)
        return user
    return dep


editor = require_role("admin", "editor")
admin = require_role("admin")


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


async def csrf_protect(request: Request):
    if request.method == "POST":
        form = await request.form()
        sent = form.get("csrf", "")
        if not sent or not hmac.compare_digest(str(sent), request.session.get("csrf", "")):
            raise HTTPException(status_code=400, detail="Form expired. Go back, refresh and try again.")


def audit(db: Session, user: User, action: str, detail: str = "") -> None:
    db.add(AuditLog(org_id=user.org_id, actor=user.email, action=action, detail=detail))


def is_platform_admin(db: Session, user: User) -> bool:
    """Who may run whole-install tasks (backups hold every organization's data). Listed in
    PRISMCIP_PLATFORM_ADMINS, or, on a single-organization install, any admin."""
    import os
    from .models import Organization
    listed = {e.strip().lower() for e in os.environ.get("PRISMCIP_PLATFORM_ADMINS", "").split(",") if e.strip()}
    if user.email.lower() in listed:
        return True
    return not listed and user.role == "admin" and db.query(Organization).count() == 1
