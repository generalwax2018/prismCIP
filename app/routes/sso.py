"""Single sign-on routes and the per-utility SSO settings."""
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import oidc, throttle
from ..auth import admin, audit, csrf_protect, start_session
from ..db import get_db
from ..members import membership, switch
from ..models import AuditLog, Organization, User
from ..web import redirect, render, s

router = APIRouter()


def _redirect_uri(request: Request) -> str:
    import os
    base = os.environ.get("PRISMCIP_BASE_URL") or str(request.base_url)
    return base.rstrip("/") + "/login/sso/callback"


@router.get("/login/sso")
def sso_form(request: Request, db: Session = Depends(get_db)):
    if not oidc.any_configured(db):
        return redirect("/login")
    return render(request, "login_sso.html")


@router.post("/login/sso", dependencies=[Depends(csrf_protect)])
async def sso_start(request: Request, db: Session = Depends(get_db)):
    f = await request.form()
    email, ip = (s(f, "email") or "").lower()[:200], throttle.client_ip(request)
    if throttle.blocked(db, email, ip, kind="sso"):
        return render(request, "login_sso.html", error=throttle.MESSAGE)
    cfg = oidc.find_settings(db, email)
    if not cfg:
        throttle.record(db, email, ip, ok=False, kind="sso")
        return render(request, "login_sso.html", error="Single sign-on isn't set up for that email. Use your password.")
    try:
        url, flow = oidc.begin(cfg, _redirect_uri(request), email)
    except oidc.OIDCError as e:
        return render(request, "login_sso.html", error=str(e))
    request.session["oidc"] = flow
    return redirect(url)


@router.get("/login/sso/callback")
def sso_callback(request: Request, db: Session = Depends(get_db)):
    flow = request.session.pop("oidc", None)
    ip = throttle.client_ip(request)
    org = db.get(Organization, flow["org_id"]) if flow and flow.get("org_id") else None
    cfg = oidc.org_settings(org) if org else oidc.env_settings()
    try:
        if not cfg:
            raise oidc.OIDCError("Single sign-on is no longer set up. Use your password.")
        email = oidc.finish(cfg, flow, dict(request.query_params), _redirect_uri(request))
    except oidc.OIDCError as e:
        throttle.record(db, "", ip, ok=False, kind="sso")
        return render(request, "login.html", error=f"Single sign-on failed: {e}", sso=True)
    user = db.query(User).filter_by(email=email, active=True).first()
    if org:
        # A utility's own identity provider may only sign in that utility's members, for its claimed domains.
        domains = [d.strip().lower() for d in (org.oidc_domain or "").split(",") if d.strip()]
        if not user or not membership(db, user.id, org.id) or email.rsplit("@", 1)[-1] not in domains:
            db.add(AuditLog(org_id=org.id, actor=email, action="sso_refused", detail=f"from {ip}"))
            db.commit()
            return render(request, "login.html", error="That account can't sign in through this utility's single "
                                                       "sign-on.")
        switch(db, user, org.id)
    elif not user:
        return render(request, "login.html", error="No PrismCIP account uses that email. Ask an admin to add you.")
    throttle.record(db, email, ip, ok=True, kind="sso")
    start_session(request, user)
    if org:
        request.session["org_lock"] = org.id  # this sign-in is good for this utility only
    audit(db, user, "login", f"single sign-on{' (' + org.name + ')' if org else ''} from {ip}")
    db.commit()
    return redirect("/")


@router.post("/settings/sso", dependencies=[Depends(csrf_protect)])
async def sso_settings(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from ..totp import seal
    org = user.org
    f = await request.form()
    if f.get("action") == "remove":
        org.oidc_issuer = org.oidc_client_id = org.oidc_client_secret = org.oidc_domain = None
        org.sso_required = False
        audit(db, user, "sso_removed")
        db.commit()
        return redirect("/settings", "Single sign-on removed.", request)
    issuer = (s(f, "oidc_issuer") or "").rstrip("/")
    domains = ",".join(sorted({d.strip().lower().lstrip("@") for d in (s(f, "oidc_domain") or "").split(",")
                               if d.strip()}))
    if not issuer or not s(f, "oidc_client_id") or not domains:
        return redirect("/settings", "Single sign-on needs the issuer, client ID and your email domain(s).", request)
    try:
        oidc._check_url(issuer)
    except oidc.OIDCError as e:
        return redirect("/settings", str(e), request)
    for other in db.query(Organization).filter(Organization.id != org.id, Organization.oidc_domain.isnot(None)).all():
        clash = set(domains.split(",")) & {d.strip() for d in other.oidc_domain.split(",")}
        if clash:
            return redirect("/settings", f"Another utility already uses single sign-on for {', '.join(clash)}.",
                            request)
    org.oidc_issuer, org.oidc_client_id, org.oidc_domain = issuer, s(f, "oidc_client_id"), domains
    if s(f, "oidc_client_secret"):
        org.oidc_client_secret = seal(s(f, "oidc_client_secret"))
    org.sso_required = f.get("sso_required") == "on"
    try:
        oidc.discovery(oidc.org_settings(org))
        msg = "Single sign-on saved; the identity provider answered."
    except oidc.OIDCError as e:
        msg = f"Saved, but the identity provider check failed: {e}"
    audit(db, user, "sso_configured", f"{issuer} for {domains}; required={org.sso_required}")
    db.commit()
    return redirect("/settings", msg, request)
