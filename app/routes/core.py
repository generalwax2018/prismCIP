"""First-run setup, login, dashboard, settings, activity log."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import throttle
from ..auth import (ROLES, admin, audit, csrf_protect, current_user, hash_password, password_problem,
                    start_session, verify_password)
from ..compliance import requirement_statuses, summary_counts
from ..db import get_db
from ..members import members as members_of
from ..models import AccessSession, Asset, AuditLog, Delegation, Organization, User, VendorAccess
from ..web import d, redirect, render, s

router = APIRouter()


@router.get("/setup")
def setup_form(request: Request, db: Session = Depends(get_db)):
    from .. import billing
    if billing.hosted():
        return redirect("/signup")
    if db.query(User).count():
        return redirect("/login")
    return render(request, "setup.html")


@router.post("/setup", dependencies=[Depends(csrf_protect)])
async def setup(request: Request, db: Session = Depends(get_db)):
    from .. import billing
    if db.query(User).count() or billing.hosted():
        return redirect("/login")
    f = await request.form()
    problem = password_problem(f.get("password", ""), s(f, "email") or "", s(f, "name") or "")
    if problem or not s(f, "email"):
        return render(request, "setup.html", error=problem or "Enter your email.")
    org = Organization(name=s(f, "org_name") or "My Utility", ncr_id=s(f, "ncr_id"),
                       regional_entity=s(f, "regional_entity"), registered_functions=s(f, "registered_functions"))
    db.add(org)
    db.flush()
    user = User(org_id=org.id, email=s(f, "email").lower(), name=s(f, "name") or s(f, "email"),
                password_hash=hash_password(f["password"]), role="admin")
    db.add(user)
    db.flush()
    from ..models import Membership
    db.add(Membership(user_id=user.id, org_id=org.id, role="admin"))
    audit(db, user, "setup", f"Created organization {org.name}")
    db.commit()
    start_session(request, user)
    return redirect("/", "Welcome to PrismCIP. Start by adding your assets.", request)


@router.get("/login")
def login_form(request: Request, db: Session = Depends(get_db)):
    from .. import billing, oidc
    if not db.query(User).count():
        return redirect("/signup" if billing.hosted() else "/setup")
    return render(request, "login.html", sso=oidc.any_configured(db), hosted=billing.hosted())


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login(request: Request, db: Session = Depends(get_db)):
    f = await request.form()
    email, ip = (s(f, "email") or "").lower()[:200], throttle.client_ip(request)
    if throttle.blocked(db, email, ip):
        return render(request, "login.html", error=throttle.MESSAGE)
    user = db.query(User).filter_by(email=email).first()
    if not user or not user.active or not verify_password(f.get("password", ""), user.password_hash):
        throttle.record(db, email, ip, ok=False)
        if user:
            audit(db, user, "login_failed", f"from {ip}")
            db.commit()
        return render(request, "login.html", error="Wrong email or password.")
    from ..auth import is_platform_admin
    from ..members import orgs_for
    orgs = [o for o, _m in orgs_for(db, user)]
    breakglass = is_platform_admin(db, user) or any(m.role == "admin" for _o, m in orgs_for(db, user))
    if orgs and all(o.sso_required and o.oidc_issuer for o in orgs) and not breakglass:
        return render(request, "login.html", error="Your utility requires single sign-on.", sso=True)
    throttle.record(db, email, ip, ok=True)
    request.session.clear()
    if user.totp_secret:
        import time
        request.session["mfa_uid"], request.session["mfa_at"], request.session["mfa_tries"] = user.id, time.time(), 0
        return redirect("/login/mfa")
    start_session(request, user)
    audit(db, user, "login", f"from {ip}")
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
    start_session(request, user)
    audit(db, user, "login", f"with two-step code from {throttle.client_ip(request)}")
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
    from ..members import membership
    target = db.get(User, uid)
    if not target or not membership(db, uid, user.org_id) or target.id == user.id:
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
    from datetime import date, timedelta
    from ..models import AuditRequest
    rfis = (db.query(AuditRequest).filter(AuditRequest.org_id == user.org_id,
                                          AuditRequest.status.in_(("Open", "In progress")),
                                          AuditRequest.due_on <= date.today() + timedelta(days=3))
            .order_by(AuditRequest.due_on).all())
    return render(request, "dashboard.html", user, statuses=statuses, counts=summary_counts(statuses),
                  access_requests=requests_, my_signoffs=my_signoffs, rfis=rfis, today=date.today(),
                  s6=s6, upcoming=upcoming, open_sessions=open_sessions,
                  n_assets=db.query(Asset).filter_by(org_id=user.org_id).count(),
                  n_paths=db.query(VendorAccess).filter_by(org_id=user.org_id, status="Enabled").count())


@router.get("/settings")
def settings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .. import backup, mailer, reminders
    from ..auth import is_platform_admin
    from .. import ai
    return render(request, "settings.html", user, org=user.org, roles=ROLES, ai_server=ai.server_configured(),
                  ai_model=ai.model(),
                  platform_admin=is_platform_admin(db, user), last_backup=backup.latest_info(),
                  reminder_items=reminders.pending(db, user.org), mail_status=mailer.describe(),
                  members=members_of(db, user.org_id),
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
    if not email or f.get("role") not in ROLES:
        return redirect("/settings", "Need an email and a role.", request)
    problem = password_problem(f.get("password", ""), email, s(f, "name") or "")
    if problem:
        return redirect("/settings", f"Temporary password: {problem}", request)
    from ..members import membership
    from ..models import Membership
    existing = db.query(User).filter_by(email=email).first()
    if existing:  # someone who already works with another utility (consultant, G&T staff): just add access
        if membership(db, existing.id, user.org_id):
            return redirect("/settings", "That person already has access here.", request)
        db.add(Membership(user_id=existing.id, org_id=user.org_id, role=f["role"]))
        audit(db, user, "member_added", f"{email} ({f['role']}), existing account")
        db.commit()
        return redirect("/settings", f"{email} already had an account; they now have access to this utility too.",
                        request)
    new = User(org_id=user.org_id, email=email, name=s(f, "name") or email, must_change_password=True,
               password_hash=hash_password(f["password"]), role=f["role"])
    db.add(new)
    db.flush()
    db.add(Membership(user_id=new.id, org_id=user.org_id, role=f["role"]))
    audit(db, user, "user_added", f"{email} ({f['role']})")
    db.commit()
    return redirect("/settings", f"Added {email}. They'll set their own password at first sign-in.", request)


@router.post("/settings/users/{uid}/toggle", dependencies=[Depends(csrf_protect)])
def toggle_user(uid: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from ..members import membership, orgs_for, switch
    target = db.get(User, uid)
    m = membership(db, uid, user.org_id) if target else None
    if not target or not m or target.id == user.id:
        return redirect("/settings", "Can't change that account.", request)
    others = [o for o, _ in orgs_for(db, target) if o.id != user.org_id]
    if others:  # they work with other utilities too: remove access here, leave their account alone
        db.delete(m)
        if target.org_id == user.org_id:
            switch(db, target, others[0].id)
        audit(db, user, "member_removed", target.email)
        db.commit()
        return redirect("/settings", f"Removed {target.email}'s access to this utility.", request)
    target.active = not target.active
    audit(db, user, "user_" + ("enabled" if target.active else "disabled"), target.email)
    db.commit()
    return redirect("/settings")


@router.post("/settings/users/{uid}/signer", dependencies=[Depends(csrf_protect)])
def toggle_signer(uid: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from ..members import membership
    target = db.get(User, uid)
    m = membership(db, uid, user.org_id) if target else None
    if not m:
        return redirect("/settings", "Can't change that account.", request)
    m.can_sign = not m.can_sign
    if target.org_id == user.org_id:
        target.can_sign = m.can_sign
    audit(db, user, "signer_" + ("granted" if m.can_sign else "removed"), target.email)
    db.commit()
    return redirect("/settings", f"{target.name} {'can now' if m.can_sign else 'can no longer'} sign here.", request)


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
    from .. import chain
    report = chain.verify(db, user.org_id)
    rows = (db.query(AuditLog).filter_by(org_id=user.org_id).order_by(AuditLog.seq.desc()).limit(500).all())
    return render(request, "activity.html", user, rows=rows, chain=report)


@router.post("/activity/anchor", dependencies=[Depends(csrf_protect)])
def activity_anchor(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from .. import chain
    n = chain.anchor_all()
    return redirect("/activity", f"Recorded {n} new anchor(s)." if n else "Anchors already current.", request)
