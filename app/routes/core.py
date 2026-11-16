"""First-run setup, login, dashboard, settings, activity log."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..auth import ROLES, admin, audit, csrf_protect, current_user, hash_password, verify_password
from ..compliance import requirement_statuses, summary_counts
from ..db import get_db
from ..models import AccessSession, Asset, AuditLog, Delegation, Organization, User, VendorAccess
from ..web import d, redirect, render, s

router = APIRouter()


@router.get("/setup")
def setup_form(request: Request, db: Session = Depends(get_db)):
    if db.query(User).count():
        return redirect("/login")
    return render(request, "setup.html")


@router.post("/setup", dependencies=[Depends(csrf_protect)])
async def setup(request: Request, db: Session = Depends(get_db)):
    if db.query(User).count():
        return redirect("/login")
    f = await request.form()
    if len(f.get("password", "")) < 12:
        return render(request, "setup.html", error="Use a password of at least 12 characters.")
    org = Organization(name=s(f, "org_name") or "My Utility", ncr_id=s(f, "ncr_id"),
                       regional_entity=s(f, "regional_entity"), registered_functions=s(f, "registered_functions"))
    db.add(org)
    db.flush()
    user = User(org_id=org.id, email=s(f, "email").lower(), name=s(f, "name") or s(f, "email"),
                password_hash=hash_password(f["password"]), role="admin")
    db.add(user)
    db.flush()
    audit(db, user, "setup", f"Created organization {org.name}")
    db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    return redirect("/", "Welcome to PrismCIP. Start by adding your assets.", request)


@router.get("/login")
def login_form(request: Request, db: Session = Depends(get_db)):
    if not db.query(User).count():
        return redirect("/setup")
    return render(request, "login.html")


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login(request: Request, db: Session = Depends(get_db)):
    f = await request.form()
    user = db.query(User).filter_by(email=(s(f, "email") or "").lower()).first()
    if not user or not user.active or not verify_password(f.get("password", ""), user.password_hash):
        return render(request, "login.html", error="Wrong email or password.")
    request.session.clear()
    if user.totp_secret:
        import time
        request.session["mfa_uid"], request.session["mfa_at"], request.session["mfa_tries"] = user.id, time.time(), 0
        return redirect("/login/mfa")
    request.session["uid"] = user.id
    audit(db, user, "login")
    db.commit()
    return redirect("/")


@router.get("/login/mfa")
def mfa_form(request: Request):
    if not request.session.get("mfa_uid"):
        return redirect("/login")
    return render(request, "login_mfa.html")


@router.post("/login/mfa", dependencies=[Depends(csrf_protect)])
async def mfa_check(request: Request, db: Session = Depends(get_db)):
    import time
    from .. import totp
    uid, started = request.session.get("mfa_uid"), request.session.get("mfa_at", 0)
    if not uid or time.time() - started > 300 or request.session.get("mfa_tries", 0) >= 5:
        request.session.clear()
        return render(request, "login.html", error="Sign-in timed out or too many tries. Start again.")
    user = db.get(User, uid)
    f = await request.form()
    secret = totp.unseal(user.totp_secret) if user and user.totp_secret else None
    step = totp.verify(secret, f.get("code", ""), user.totp_last_step) if secret else None
    if step is None:
        request.session["mfa_tries"] = request.session.get("mfa_tries", 0) + 1
        return render(request, "login_mfa.html", error="That code didn't work. Use the current code from your app.")
    user.totp_last_step = step
    request.session.clear()
    request.session["uid"] = user.id
    audit(db, user, "login", "with two-step code")
    db.commit()
    return redirect("/")


@router.get("/settings/mfa")
def mfa_setup(request: Request, user: User = Depends(current_user)):
    from .. import totp
    if user.totp_secret:
        return render(request, "mfa.html", user, enrolled=True)
    secret = request.session.get("mfa_new") or totp.new_secret()
    request.session["mfa_new"] = secret
    uri = totp.uri(secret, user.email, f"PrismCIP {user.org.name}"[:60])
    return render(request, "mfa.html", user, enrolled=False, secret=secret, qr=totp.qr_svg(uri))


@router.post("/settings/mfa", dependencies=[Depends(csrf_protect)])
async def mfa_change(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .. import totp
    f = await request.form()
    if f.get("action") == "enable":
        secret = request.session.get("mfa_new")
        step = totp.verify(secret, f.get("code", "")) if secret else None
        if step is None:
            return redirect("/settings/mfa", "That code didn't match. Check the time on your phone and try again.",
                            request)
        user.totp_secret, user.totp_last_step = totp.seal(secret), step
        request.session.pop("mfa_new", None)
        audit(db, user, "mfa_enabled")
        db.commit()
        return redirect("/settings", "Two-step sign-in is on.", request)
    if f.get("action") == "disable":
        secret = totp.unseal(user.totp_secret) if user.totp_secret else None
        if not verify_password(f.get("password", ""), user.password_hash) or not secret or \
                totp.verify(secret, f.get("code", ""), user.totp_last_step) is None:
            return redirect("/settings/mfa", "Password or code didn't match. Two-step sign-in is still on.", request)
        user.totp_secret, user.totp_last_step = None, None
        audit(db, user, "mfa_disabled")
        db.commit()
        return redirect("/settings", "Two-step sign-in is off.", request)
    return redirect("/settings/mfa")


@router.post("/settings/users/{uid}/reset-mfa", dependencies=[Depends(csrf_protect)])
def reset_mfa(uid: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    target = db.get(User, uid)
    if not target or target.org_id != user.org_id or target.id == user.id:
        return redirect("/settings", "Can't change that account.", request)
    target.totp_secret, target.totp_last_step = None, None
    audit(db, user, "mfa_reset", target.email)
    db.commit()
    return redirect("/settings", f"Two-step sign-in reset for {target.email}. They can set it up again.", request)


@router.post("/logout", dependencies=[Depends(csrf_protect)])
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    statuses = requirement_statuses(db, user.org)
    s6 = [x for x in statuses if x.req.section6]
    upcoming = sorted([x for x in statuses if x.due], key=lambda x: x.due)
    open_sessions = (db.query(AccessSession).filter_by(org_id=user.org_id, ended_at=None)
                     .order_by(AccessSession.started_at).all())
    from ..models import AccessApproval, Signoff
    requests_ = (db.query(AccessApproval).filter_by(org_id=user.org_id, status="Requested")
                 .order_by(AccessApproval.starts_at).all())
    my_signoffs = db.query(Signoff).filter_by(org_id=user.org_id, signer_id=user.id, status="Pending").all()
    return render(request, "dashboard.html", user, statuses=statuses, counts=summary_counts(statuses),
                  access_requests=requests_, my_signoffs=my_signoffs,
                  s6=s6, upcoming=upcoming, open_sessions=open_sessions,
                  n_assets=db.query(Asset).filter_by(org_id=user.org_id).count(),
                  n_paths=db.query(VendorAccess).filter_by(org_id=user.org_id, status="Enabled").count())


@router.get("/settings")
def settings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .. import mailer, reminders
    return render(request, "settings.html", user, org=user.org, roles=ROLES,
                  reminder_items=reminders.pending(db, user.org), mail_status=mailer.describe(),
                  users=db.query(User).filter_by(org_id=user.org_id).order_by(User.email).all(),
                  delegations=db.query(Delegation).filter_by(org_id=user.org_id)
                  .order_by(Delegation.effective_on.desc()).all())


@router.post("/settings/org", dependencies=[Depends(csrf_protect)])
async def save_org(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    f = await request.form()
    org = user.org
    before = org.cip_senior_manager
    for k in ("name", "ncr_id", "regional_entity", "registered_functions", "cip_senior_manager", "audit_id"):
        setattr(org, k, s(f, k))
    org.name = org.name or "My Utility"
    org.cip_senior_manager_since = d(f, "cip_senior_manager_since")
    org.audit_period_start, org.audit_period_end = d(f, "audit_period_start"), d(f, "audit_period_end")
    if before != org.cip_senior_manager:
        audit(db, user, "cip_senior_manager_changed", f"{before or '—'} → {org.cip_senior_manager or '—'}")
    audit(db, user, "org_updated")
    db.commit()
    return redirect("/settings", "Organization saved.", request)


@router.post("/settings/users", dependencies=[Depends(csrf_protect)])
async def add_user(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    f = await request.form()
    email = (s(f, "email") or "").lower()
    if not email or len(f.get("password", "")) < 12 or f.get("role") not in ROLES:
        return redirect("/settings", "Need an email, a role and a password of 12+ characters.", request)
    if db.query(User).filter_by(email=email).first():
        return redirect("/settings", "That email already has an account.", request)
    db.add(User(org_id=user.org_id, email=email, name=s(f, "name") or email,
                password_hash=hash_password(f["password"]), role=f["role"]))
    audit(db, user, "user_added", f"{email} ({f['role']})")
    db.commit()
    return redirect("/settings", f"Added {email}.", request)


@router.post("/settings/users/{uid}/toggle", dependencies=[Depends(csrf_protect)])
def toggle_user(uid: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    target = db.get(User, uid)
    if not target or target.org_id != user.org_id or target.id == user.id:
        return redirect("/settings", "Can't change that account.", request)
    target.active = not target.active
    audit(db, user, "user_" + ("enabled" if target.active else "disabled"), target.email)
    db.commit()
    return redirect("/settings")


@router.post("/settings/users/{uid}/signer", dependencies=[Depends(csrf_protect)])
def toggle_signer(uid: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    target = db.get(User, uid)
    if not target or target.org_id != user.org_id:
        return redirect("/settings", "Can't change that account.", request)
    target.can_sign = not target.can_sign
    audit(db, user, "signer_" + ("granted" if target.can_sign else "removed"), target.email)
    db.commit()
    return redirect("/settings", f"{target.name} {'can now' if target.can_sign else 'can no longer'} sign.", request)


@router.post("/settings/me", dependencies=[Depends(csrf_protect)])
async def save_me(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = await request.form()
    user.notify = f.get("notify") == "on"
    if s(f, "name"):
        user.name = s(f, "name")
    audit(db, user, "account_updated", f"reminders {'on' if user.notify else 'off'}")
    db.commit()
    return redirect("/settings", "Your account was saved.", request)


@router.post("/settings/reminders/send", dependencies=[Depends(csrf_protect)])
def send_reminders(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from .. import reminders
    r = reminders.send_due(db, user.org, base_url=str(request.base_url).rstrip("/"))
    audit(db, user, "reminders_sent", f"{r['sent']} item(s), {r['messages']} message(s)")
    db.commit()
    return redirect("/settings", f"Sent {r['sent']} reminder item(s) in {r['messages']} message(s).", request)


@router.post("/settings/delegations", dependencies=[Depends(csrf_protect)])
async def add_delegation(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    f = await request.form()
    if not s(f, "delegate_name") or not s(f, "authority") or not d(f, "effective_on"):
        return redirect("/settings", "Delegation needs a name, the authority and an effective date.", request)
    db.add(Delegation(org_id=user.org_id, delegate_name=s(f, "delegate_name"),
                      delegate_title=s(f, "delegate_title"), authority=s(f, "authority"),
                      effective_on=d(f, "effective_on")))
    audit(db, user, "delegation_added", s(f, "delegate_name"))
    db.commit()
    return redirect("/settings", "Delegation recorded.", request)


@router.post("/settings/delegations/{did}/revoke", dependencies=[Depends(csrf_protect)])
async def revoke_delegation(did: int, request: Request, user: User = Depends(admin),
                            db: Session = Depends(get_db)):
    from datetime import date
    dl = db.get(Delegation, did)
    if dl and dl.org_id == user.org_id and not dl.revoked_on:
        dl.revoked_on = date.today()
        audit(db, user, "delegation_revoked", dl.delegate_name)
        db.commit()
    return redirect("/settings")


@router.get("/activity")
def activity(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = (db.query(AuditLog).filter_by(org_id=user.org_id).order_by(AuditLog.id.desc()).limit(500).all())
    return render(request, "activity.html", user, rows=rows)
