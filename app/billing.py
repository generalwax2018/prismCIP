"""Hosted self-service signup and Stripe subscriptions.

Off unless PRISMCIP_HOSTED=1. Stripe is called over its REST API with urllib (no SDK). Settings:
  PRISMCIP_HOSTED=1                 turn on /signup and trial gating
  PRISMCIP_TRIAL_DAYS=30            free trial length
  PRISMCIP_GRACE_DAYS=14            how long a failed payment keeps the account writable
  PRISMCIP_STRIPE_SECRET_KEY        sk_test_... (or sk_live_...)
  PRISMCIP_STRIPE_PRICE_ID          price_... for the subscription
  PRISMCIP_STRIPE_WEBHOOK_SECRET    whsec_... from the webhook endpoint (/billing/webhook)
  PRISMCIP_STRIPE_API               override the API base (tests point it at a loopback fake)

An organization whose trial has ended without a subscription, or whose subscription is canceled or unpaid past the
grace period, becomes read-only: everyone can still sign in, read and export, but changes wait for billing."""
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

WRITABLE = ("trialing", "active", "past_due")
ALLOWED_WHEN_LOCKED = ("/billing", "/account", "/logout", "/orgs/switch", "/settings/mfa", "/login")


class BillingError(RuntimeError):
    pass


class BillingRequired(Exception):
    pass


def hosted() -> bool:
    return os.environ.get("PRISMCIP_HOSTED", "").lower() in ("1", "true", "yes", "on")


def stripe_configured() -> bool:
    return bool(os.environ.get("PRISMCIP_STRIPE_SECRET_KEY") and os.environ.get("PRISMCIP_STRIPE_PRICE_ID"))


def trial_days() -> int:
    return max(1, int(os.environ.get("PRISMCIP_TRIAL_DAYS", "30") or 30))


def grace_days() -> int:
    return max(0, int(os.environ.get("PRISMCIP_GRACE_DAYS", "14") or 14))


def state(org, today: date | None = None) -> dict:
    """What the billing banner and the write gate need."""
    today = today or date.today()
    st = org.plan_status
    if not hosted() or st is None:
        return dict(gated=False, locked=False, status=None)
    days_left = (org.trial_ends - today).days if org.trial_ends else 0
    locked = False
    if st == "trialing":
        locked = days_left < 0
    elif st == "past_due":
        locked = bool(org.paid_through) and (today - org.paid_through).days > grace_days()
    elif st != "active":
        locked = True
    return dict(gated=True, locked=locked, status=st, days_left=days_left, trial_ends=org.trial_ends,
                paid_through=org.paid_through, can_pay=stripe_configured())


def check_write(request, user) -> None:
    """Called for every change (POST) made through the role checks; raises BillingRequired when read-only."""
    if request.method != "POST" or not hosted() or user.org is None or user.org.plan_status is None:
        return
    if any(request.url.path.startswith(p) for p in ALLOWED_WHEN_LOCKED):
        return
    if state(user.org)["locked"]:
        raise BillingRequired()


# ------------------------------------------------------------------ Stripe REST
def _api_base() -> str:
    base = (os.environ.get("PRISMCIP_STRIPE_API") or "https://api.stripe.com").rstrip("/")
    u = urlparse(base)
    if not (u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"))):
        raise BillingError("PRISMCIP_STRIPE_API must be https.")
    return base


def _flatten(data: dict, prefix: str = "") -> list[tuple[str, str]]:
    out = []
    for k, v in data.items():
        key = f"{prefix}[{k}]" if prefix else k
        if isinstance(v, dict):
            out += _flatten(v, key)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                out += _flatten(item, f"{key}[{i}]") if isinstance(item, dict) else [(f"{key}[{i}]", str(item))]
        elif v is not None:
            out.append((key, "true" if v is True else "false" if v is False else str(v)))
    return out


def stripe(method: str, path: str, data: dict | None = None, idempotency_key: str | None = None) -> dict:
    key = os.environ.get("PRISMCIP_STRIPE_SECRET_KEY") or ""
    if not key:
        raise BillingError("Billing isn't configured.")
    body = urlencode(_flatten(data or {})).encode() if data is not None else None
    req = urllib.request.Request(_api_base() + path, data=body, method=method)
    req.add_header("Authorization", "Basic " + b64encode(f"{key}:".encode()).decode())
    req.add_header("Stripe-Version", "2024-06-20")
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if idempotency_key:
        req.add_header("Idempotency-Key", idempotency_key)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read(2_000_000))
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read(100_000)).get("error", {}).get("message", "")
        except ValueError:
            msg = ""
        raise BillingError(f"Stripe said: {msg or e.reason}"[:300])
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise BillingError(f"Couldn't reach Stripe: {e}"[:300])


def ensure_customer(org) -> str:
    if org.stripe_customer_id:
        return org.stripe_customer_id
    c = stripe("POST", "/v1/customers", {"name": org.name, "email": org.billing_email,
                                          "metadata": {"prismcip_org_id": org.id}},
               idempotency_key=f"prismcip-customer-{org.id}")
    org.stripe_customer_id = c["id"]
    return c["id"]


def checkout_url(org, base_url: str) -> str:
    cust = ensure_customer(org)
    sess = stripe("POST", "/v1/checkout/sessions", {
        "mode": "subscription", "customer": cust, "client_reference_id": str(org.id),
        "line_items": [{"price": os.environ["PRISMCIP_STRIPE_PRICE_ID"], "quantity": 1}],
        "subscription_data": {"metadata": {"prismcip_org_id": org.id}},
        "success_url": base_url + "/billing?done=1", "cancel_url": base_url + "/billing",
    })
    return sess["url"]


def portal_url(org, base_url: str) -> str:
    if not org.stripe_customer_id:
        raise BillingError("There's no subscription to manage yet.")
    return stripe("POST", "/v1/billing_portal/sessions", {"customer": org.stripe_customer_id,
                                                          "return_url": base_url + "/billing"})["url"]


# ------------------------------------------------------------------ webhooks
TOLERANCE = 300


def verify_signature(payload: bytes, header: str, secret: str, now: float | None = None) -> dict:
    """Stripe's scheme: header 't=<unix>,v1=<hex hmac-sha256 of "t.payload">' (several v1 allowed)."""
    if not secret:
        raise BillingError("Webhook secret isn't configured.")
    parts = {}
    for item in (header or "").split(","):
        k, _, v = item.strip().partition("=")
        parts.setdefault(k, []).append(v)
    try:
        ts = int(parts.get("t", [""])[0])
    except ValueError:
        raise BillingError("Malformed signature header.")
    now = time.time() if now is None else now
    if abs(now - ts) > TOLERANCE:
        raise BillingError("Signature timestamp is outside the tolerance.")
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, v) for v in parts.get("v1", [])):
        raise BillingError("Signature doesn't match.")
    try:
        return json.loads(payload)
    except ValueError:
        raise BillingError("Body isn't JSON.")


def _day(ts) -> date | None:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).date()
    except (TypeError, ValueError, OSError):
        return None


def apply_event(db, event: dict) -> str:
    from .models import AuditLog, BillingEvent, Organization
    eid, kind = str(event.get("id") or ""), str(event.get("type") or "")
    if not eid:
        return "ignored"
    if db.get(BillingEvent, eid):
        return "duplicate"
    obj = (event.get("data") or {}).get("object") or {}
    org = None
    meta_org = (obj.get("metadata") or {}).get("prismcip_org_id") or obj.get("client_reference_id")
    cust = obj.get("customer") if isinstance(obj.get("customer"), str) else None
    if cust:
        org = db.query(Organization).filter_by(stripe_customer_id=cust).first()
    if org is None and meta_org and str(meta_org).isdigit():
        org = db.get(Organization, int(meta_org))
        if org and org.stripe_customer_id and cust and org.stripe_customer_id != cust:
            org = None  # metadata can't move an org onto someone else's customer
    result = "ignored"
    if org is not None:
        if kind == "checkout.session.completed" and obj.get("mode") == "subscription":
            org.stripe_customer_id = org.stripe_customer_id or cust
            org.stripe_subscription_id = obj.get("subscription") or org.stripe_subscription_id
            org.plan_status = "active"
            result = "activated"
        elif kind in ("customer.subscription.created", "customer.subscription.updated",
                      "customer.subscription.deleted"):
            st = "canceled" if kind.endswith("deleted") else str(obj.get("status") or "")
            mapped = {"trialing": "active", "active": "active", "past_due": "past_due", "unpaid": "unpaid",
                      "canceled": "canceled", "incomplete_expired": "canceled", "incomplete": org.plan_status,
                      "paused": "unpaid"}.get(st)
            if mapped:
                org.plan_status = mapped
            org.stripe_subscription_id = obj.get("id") or org.stripe_subscription_id
            org.paid_through = _day(obj.get("current_period_end")) or org.paid_through
            result = f"subscription {st}"
        elif kind == "invoice.paid":
            org.plan_status = "active"
            lines = ((obj.get("lines") or {}).get("data") or [{}])
            org.paid_through = _day(((lines[0] or {}).get("period") or {}).get("end")) or org.paid_through
            result = "paid"
        elif kind == "invoice.payment_failed":
            if org.plan_status == "active":
                org.plan_status = "past_due"
            result = "payment failed"
        if result != "ignored":
            db.add(AuditLog(org_id=org.id, actor="stripe", action="billing", detail=f"{kind}: {result}"))
    db.add(BillingEvent(id=eid[:100], kind=kind[:100], org_id=org.id if org else None))
    db.commit()
    return result


def start_trial(org) -> None:
    org.plan_status = "trialing"
    org.trial_ends = date.today() + timedelta(days=trial_days())
