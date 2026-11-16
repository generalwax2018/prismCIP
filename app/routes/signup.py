"""Hosted self-service signup, the billing page and the Stripe webhook."""
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .. import billing, mailer, throttle
from ..auth import admin, audit, csrf_protect, current_user, hash_password, password_problem, start_session
from ..db import get_db
from ..models import AuditLog, Membership, Organization, User
from ..web import redirect, render, s

router = APIRouter()
REGIONS = ["MRO", "NPCC", "RF", "SERC", "Texas RE", "WECC"]


def _base(request: Request) -> str:
    return (os.environ.get("PRISMCIP_BASE_URL") or str(request.base_url)).rstrip("/")


@router.get("/signup")
def signup_form(request: Request):
    if not billing.hosted():
        raise HTTPException(404)
    return render(request, "signup.html", regions=REGIONS, trial=billing.trial_days())


@router.post("/signup", dependencies=[Depends(csrf_protect)])
async def signup(request: Request, db: Session = Depends(get_db)):
    if not billing.hosted():
        raise HTTPException(404)
    f = await request.form()
    ip = throttle.client_ip(request)
    email, name, org_name = (s(f, "email") or "").lower()[:200], s(f, "name") or "", s(f, "org_name") or ""

    def again(msg):
        return render(request, "signup.html", regions=REGIONS, trial=billing.trial_days(), error=msg,
                      form={k: f.get(k, "") for k in ("org_name", "name", "email", "ncr_id", "regional_entity")})
    if throttle.blocked(db, "", ip, kind="signup"):
        return again(throttle.MESSAGE)
    throttle.record(db, email, ip, ok=False, kind="signup")  # every attempt counts toward the per-IP limit
    db.commit()
    if f.get("website"):  # honeypot field, hidden from people
        return again("Something went wrong. Try again.")
    if not (email and "@" in email and name and org_name):
        return again("Fill in the utility, your name and your work email.")
    if f.get("terms") != "on":
        return again("Accept the terms to continue.")
    problem = password_problem(f.get("password", ""), email, name)
    if problem:
        return again(problem)
    if db.query(User).filter_by(email=email).first():
        return again("There's already an account for that email. Sign in, or reset your password.")
    org = Organization(name=org_name[:200], ncr_id=s(f, "ncr_id"), billing_email=email,
                       regional_entity=f.get("regional_entity") if f.get("regional_entity") in REGIONS else None)
    billing.start_trial(org)
    db.add(org)
    db.flush()
    user = User(org_id=org.id, email=email, name=name[:200], password_hash=hash_password(f["password"]),
                role="admin", can_sign=True)
    db.add(user)
    db.flush()
    db.add(Membership(user_id=user.id, org_id=org.id, role="admin", can_sign=True))
    audit(db, user, "signup", f"{org.name}; trial to {org.trial_ends} from {ip}")
    db.commit()
    try:
        mailer.send([email], "Welcome to PrismCIP",
                    f"Hi {name},\n\nYour PrismCIP workspace for {org.name} is ready. The free trial runs to "
                    f"{org.trial_ends}.\n\nSign in: {_base(request)}/login\n")
    except Exception:  # mail is best effort; the account works either way
        pass
    start_session(request, user)
    return redirect("/", f"Welcome. Your free trial runs to {org.trial_ends}. Start by adding your assets.", request)


@router.get("/billing")
def billing_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not billing.hosted():
        raise HTTPException(404)
    st = billing.state(user.org)
    events = (db.query(AuditLog).filter_by(org_id=user.org_id, action="billing").order_by(AuditLog.id.desc())
              .limit(10).all())
    return render(request, "billing.html", user, org=user.org, st=st, events=events,
                  done=request.query_params.get("done") == "1")


@router.post("/billing/checkout", dependencies=[Depends(csrf_protect)])
async def checkout(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    if not (billing.hosted() and billing.stripe_configured()):
        raise HTTPException(404)
    if user.org.plan_status == "active" and user.org.stripe_subscription_id:
        return redirect("/billing", "There's already an active subscription. Use Manage billing.", request)
    try:
        url = billing.checkout_url(user.org, _base(request))
    except billing.BillingError as e:
        db.commit()
        return redirect("/billing", str(e), request)
    audit(db, user, "billing_checkout_started")
    db.commit()
    return redirect(url)


@router.post("/billing/portal", dependencies=[Depends(csrf_protect)])
async def portal(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    if not (billing.hosted() and billing.stripe_configured()):
        raise HTTPException(404)
    try:
        return redirect(billing.portal_url(user.org, _base(request)))
    except billing.BillingError as e:
        return redirect("/billing", str(e), request)


@router.post("/billing/webhook")
async def webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    if len(payload) > 1_000_000:
        return JSONResponse({"error": "too large"}, status_code=413)
    try:
        event = billing.verify_signature(payload, request.headers.get("stripe-signature", ""),
                                         os.environ.get("PRISMCIP_STRIPE_WEBHOOK_SECRET", ""))
    except billing.BillingError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse({"result": billing.apply_event(db, event)})
