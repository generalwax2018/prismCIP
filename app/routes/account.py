"""Change password, forgot / reset password, and admin password resets."""
import hashlib
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import mailer, throttle
from ..auth import (admin, audit, csrf_protect, current_user, hash_password, password_problem, start_session,
                    verify_password)
from ..db import get_db
from ..models import PasswordReset, User, utcnow
from ..web import redirect, render, s

router = APIRouter()
RESET_TTL = timedelta(hours=1)
SENT = "If that email has an account, a reset link is on its way. It works once, for one hour."


def _set_password(db: Session, user: User, password: str) -> None:
    user.password_hash = hash_password(password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    user.session_version = (user.session_version or 1) + 1  # signs out every other session
    db.query(PasswordReset).filter_by(user_id=user.id, used_at=None).update({"used_at": utcnow()})


def _issue_reset(db: Session, user: User, base_url: str) -> str:
    tok = secrets.token_urlsafe(32)
    db.add(PasswordReset(user_id=user.id, token_hash=hashlib.sha256(tok.encode()).hexdigest(),
                         expires_at=utcnow() + RESET_TTL))
    link = f"{base_url.rstrip('/')}/reset/{tok}"
    mailer.send([user.email], "PrismCIP: reset your password",
                f"Someone asked to reset the PrismCIP password for {user.email}.\n\n"
                f"Set a new password here (works once, for one hour):\n{link}\n\n"
                f"If that wasn't you, ignore this email; your password hasn't changed.")
    return link


@router.get("/account/password")
def change_form(request: Request, user: User = Depends(current_user)):
    return render(request, "account_password.html", user, forced=user.must_change_password)


@router.post("/account/password", dependencies=[Depends(csrf_protect)])
async def change(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = await request.form()
    new, again = f.get("new_password", ""), f.get("confirm", "")
    if not verify_password(f.get("current_password", ""), user.password_hash):
        return render(request, "account_password.html", user, forced=user.must_change_password,
                      error="Current password is wrong.")
    problem = password_problem(new, user.email, user.name)
    if problem or new != again or verify_password(new, user.password_hash):
        return render(request, "account_password.html", user, forced=user.must_change_password,
                      error=problem or ("The two new passwords don't match." if new != again
                                        else "Pick a password different from the current one."))
    _set_password(db, user, new)
    audit(db, user, "password_changed")
    db.commit()
    start_session(request, user)  # keep this browser signed in on the new session version
    return redirect("/", "Password changed. Other sessions were signed out.", request)


@router.get("/forgot")
def forgot_form(request: Request):
    return render(request, "forgot.html")


@router.post("/forgot", dependencies=[Depends(csrf_protect)])
async def forgot(request: Request, db: Session = Depends(get_db)):
    f = await request.form()
    email, ip = (s(f, "email") or "").lower()[:200], throttle.client_ip(request)
    if throttle.blocked(db, email, ip, kind="forgot"):
        return render(request, "forgot.html", sent=SENT)  # same answer either way
    throttle.record(db, email, ip, ok=False, kind="forgot")  # every request counts toward the limit
    user = db.query(User).filter_by(email=email, active=True).first()
    if user:
        _issue_reset(db, user, str(request.base_url))
        audit(db, user, "password_reset_requested", f"from {ip}")
        db.commit()
    return render(request, "forgot.html", sent=SENT)


def _valid(db: Session, token: str) -> PasswordReset | None:
    if not token or len(token) > 100:
        return None
    r = db.query(PasswordReset).filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first()
    if not r or r.used_at or r.expires_at < utcnow():
        return None
    return r


@router.get("/reset/{token}")
def reset_form(token: str, request: Request, db: Session = Depends(get_db)):
    if not _valid(db, token):
        return render(request, "reset.html", expired=True)
    return render(request, "reset.html", token=token)


@router.post("/reset/{token}", dependencies=[Depends(csrf_protect)])
async def reset(token: str, request: Request, db: Session = Depends(get_db)):
    r = _valid(db, token)
    if not r:
        return render(request, "reset.html", expired=True)
    user = db.get(User, r.user_id)
    if not user or not user.active:
        return render(request, "reset.html", expired=True)
    f = await request.form()
    new, again = f.get("new_password", ""), f.get("confirm", "")
    problem = password_problem(new, user.email, user.name)
    if problem or new != again:
        return render(request, "reset.html", token=token,
                      error=problem or "The two passwords don't match.")
    _set_password(db, user, new)
    r.used_at = utcnow()
    audit(db, user, "password_reset_completed", f"from {throttle.client_ip(request)}")
    db.commit()
    request.session.clear()
    return render(request, "login.html", error=None, notice="Password set. Sign in with your new password.")


@router.post("/settings/users/{uid}/password", dependencies=[Depends(csrf_protect)])
async def admin_reset(uid: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from ..members import membership
    target = db.get(User, uid)
    if not target or not membership(db, uid, user.org_id):
        raise HTTPException(404)
    f = await request.form()
    if f.get("action") == "temp":
        temp = "-".join(secrets.token_hex(3) for _ in range(4))  # e.g. 3f2a1c-9b0d2e-77aa10-c4e5f6
        target.password_hash = hash_password(temp)
        target.must_change_password = True
        target.session_version = (target.session_version or 1) + 1
        audit(db, user, "password_temp_set", target.email)
        db.commit()
        return redirect("/settings", f"Temporary password for {target.email} (shown once; they must change it "
                                     f"at sign-in): {temp}", request)
    _issue_reset(db, target, str(request.base_url))
    audit(db, user, "password_reset_sent", target.email)
    db.commit()
    return redirect("/settings", f"Reset link sent to {target.email}.", request)
