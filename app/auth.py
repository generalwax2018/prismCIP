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


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("uid")
    user = db.get(User, uid) if uid else None
    if not user or not user.active:
        raise LoginRequired()
    return user


def require_role(*roles):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Your role can't do that.")
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
