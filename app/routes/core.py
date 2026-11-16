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
    request.session["uid"] = user.id
    audit(db, user, "login")
    db.commit()
    return redirect("/")


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
    return render(request, "dashboard.html", user, statuses=statuses, counts=summary_counts(statuses),
                  s6=s6, upcoming=upcoming, open_sessions=open_sessions,
                  n_assets=db.query(Asset).filter_by(org_id=user.org_id).count(),
                  n_paths=db.query(VendorAccess).filter_by(org_id=user.org_id, status="Enabled").count())


@router.get("/settings")
def settings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "settings.html", user, org=user.org, roles=ROLES,
                  users=db.query(User).filter_by(org_id=user.org_id).order_by(User.email).all(),
                  delegations=db.query(Delegation).filter_by(org_id=user.org_id)
                  .order_by(Delegation.effective_on.desc()).all())


@router.post("/settings/org", dependencies=[Depends(csrf_protect)])
async def save_org(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    f = await request.form()
    org = user.org
    before = org.cip_senior_manager
    for k in ("name", "ncr_id", "regional_entity", "registered_functions", "cip_senior_manager"):
        setattr(org, k, s(f, k))
    org.cip_senior_manager_since = d(f, "cip_senior_manager_since")
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
