"""Hosted signup, trial gating and Stripe billing against a loopback fake of the Stripe API."""
import hashlib
import hmac
import json
import threading
import time
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app import billing
from app.db import SessionLocal
from app.main import app
from app.models import Asset, BillingEvent, Organization, User

PW = "harbor-lantern-quartz"
WHSEC = "whsec_test_123"


class Fake:
    calls: list = []


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        form = {k: v[0] for k, v in parse_qs(body).items()}
        Fake.calls.append((self.path, form, self.headers.get("Authorization"), self.headers.get("Idempotency-Key")))
        port = self.server.server_port
        if self.path == "/v1/customers":
            out = {"id": "cus_TEST1", "object": "customer"}
        elif self.path == "/v1/checkout/sessions":
            out = {"id": "cs_TEST1", "url": f"http://127.0.0.1:{port}/pay/cs_TEST1"}
        elif self.path == "/v1/billing_portal/sessions":
            out = {"id": "bps_1", "url": f"http://127.0.0.1:{port}/portal/bps_1"}
        else:
            out, code = {"error": {"message": "No such route"}}, 404
            return self._send(out, code)
        self._send(out)

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


@pytest.fixture()
def hosted(monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for k, v in {"PRISMCIP_HOSTED": "1", "PRISMCIP_STRIPE_SECRET_KEY": "sk_test_abc",
                 "PRISMCIP_STRIPE_PRICE_ID": "price_TEST", "PRISMCIP_STRIPE_WEBHOOK_SECRET": WHSEC,
                 "PRISMCIP_STRIPE_API": f"http://127.0.0.1:{srv.server_port}", "PRISMCIP_TRIAL_DAYS": "30"}.items():
        monkeypatch.setenv(k, v)
    yield
    srv.shutdown()


def _csrf(c, url="/"):
    return CSRF.search(c.get(url).text).group(1)


def _hook(c, event, secret=WHSEC, ts=None):
    body = json.dumps(event).encode()
    ts = int(time.time()) if ts is None else ts
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return c.post("/billing/webhook", content=body, headers={"Stripe-Signature": f"t={ts},v1={sig}",
                                                             "Content-Type": "application/json"})


def test_self_hosted_has_no_signup_or_billing():
    with TestClient(app) as c:
        assert c.get("/signup").status_code == 404
        assert "free trial" not in c.get("/login").text


def test_signature_checks():
    body = b'{"id":"evt_1"}'
    ts = int(time.time())
    good = hmac.new(b"s", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert billing.verify_signature(body, f"t={ts},v1=deadbeef,v1={good}", "s")["id"] == "evt_1"
    for hdr, now in ((f"t={ts},v1={good}", ts + 301), (f"t={ts},v1={'0' * 64}", ts), ("garbage", ts)):
        with pytest.raises(billing.BillingError):
            billing.verify_signature(body, hdr, "s", now=now)


def test_signup_trial_gate_checkout_and_webhooks(hosted):
    with TestClient(app) as c:
        assert "Start a free trial" in c.get("/login").text
        form = dict(csrf=_csrf(c, "/signup"), org_name="Sagebrush Electric Co-op", name="Sam Sage",
                    email="sam@sagebrush.test", password=PW, terms="on", regional_entity="WECC")
        assert "already an account" in c.post("/signup", data=dict(form, email="admin@coop.test")).text
        assert "Accept the terms" in c.post("/signup", data={k: v for k, v in form.items() if k != "terms"}).text
        r = c.post("/signup", data=form)
        assert "free trial runs to" in r.text and "Sagebrush Electric Co-op" in r.text
        with SessionLocal() as db:
            org = db.query(Organization).filter_by(name="Sagebrush Electric Co-op").one()
            oid = org.id
            assert org.plan_status == "trialing" and org.trial_ends == date.today() + timedelta(days=30)
        # during the trial, changes work
        c.post("/assets/new", data=dict(csrf=_csrf(c, "/assets/new"), name="Sage Sub 1", asset_type="Substation"))
        # trial ends: read-only, exports still work
        with SessionLocal() as db:
            db.get(Organization, oid).trial_ends = date.today() - timedelta(days=1)
            db.commit()
        page = c.get("/assets").text
        assert "Sage Sub 1" in page and "free trial has ended" in page
        r = c.post("/assets/new", data=dict(csrf=_csrf(c, "/assets/new"), name="Sage Sub 2", asset_type="Substation"))
        assert "Changes are paused" in r.text and r.url.path == "/billing"
        with SessionLocal() as db:
            assert not db.query(Asset).filter_by(org_id=oid, name="Sage Sub 2").count()
        assert c.get("/readiness.csv").status_code == 200
        # subscribe: customer + checkout session through the Stripe API
        r = c.post("/billing/checkout", data=dict(csrf=_csrf(c, "/billing")), follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].endswith("/pay/cs_TEST1")
        paths = [p for p, *_ in Fake.calls]
        assert paths[-2:] == ["/v1/customers", "/v1/checkout/sessions"]
        _p, sess, auth, _i = Fake.calls[-1]
        assert sess["line_items[0][price]"] == "price_TEST" and sess["customer"] == "cus_TEST1"
        assert sess["client_reference_id"] == str(oid) and auth.startswith("Basic ")
        assert Fake.calls[-2][3] == f"prismcip-customer-{oid}"
        # forged / unsigned webhooks do nothing
        evt = {"id": "evt_A", "type": "checkout.session.completed",
               "data": {"object": {"mode": "subscription", "customer": "cus_TEST1", "subscription": "sub_1",
                                   "client_reference_id": str(oid)}}}
        assert _hook(c, evt, secret="wrong").status_code == 400
        assert _hook(c, evt, ts=int(time.time()) - 3600).status_code == 400
        with SessionLocal() as db:
            assert db.get(Organization, oid).plan_status == "trialing"
        assert _hook(c, evt).json()["result"] == "activated"
        assert _hook(c, evt).json()["result"] == "duplicate"
        period_end = int(time.time()) + 30 * 86400
        _hook(c, {"id": "evt_B", "type": "customer.subscription.updated",
                  "data": {"object": {"id": "sub_1", "customer": "cus_TEST1", "status": "active",
                                      "current_period_end": period_end}}})
        with SessionLocal() as db:
            org = db.get(Organization, oid)
            assert org.plan_status == "active" and org.stripe_subscription_id == "sub_1" and org.paid_through
        c.post("/assets/new", data=dict(csrf=_csrf(c, "/assets/new"), name="Sage Sub 2", asset_type="Substation"))
        assert "Sage Sub 2" in c.get("/assets").text
        assert "Manage billing" in c.get("/billing").text
        r = c.post("/billing/portal", data=dict(csrf=_csrf(c, "/billing")), follow_redirects=False)
        assert r.headers["location"].endswith("/portal/bps_1")
        # payment fails: past due but still writable during grace; canceled locks again
        _hook(c, {"id": "evt_C", "type": "invoice.payment_failed", "data": {"object": {"customer": "cus_TEST1"}}})
        assert "last payment" in c.get("/").text
        _hook(c, {"id": "evt_D", "type": "customer.subscription.deleted",
                  "data": {"object": {"id": "sub_1", "customer": "cus_TEST1", "status": "canceled"}}})
        r = c.post("/assets/new", data=dict(csrf=_csrf(c, "/assets/new"), name="Sage Sub 3", asset_type="Substation"))
        assert "Changes are paused" in r.text
        # an event for another org's customer can't be steered onto this one by metadata
        assert _hook(c, {"id": "evt_E", "type": "checkout.session.completed",
                         "data": {"object": {"mode": "subscription", "customer": "cus_OTHER",
                                             "client_reference_id": str(oid)}}}).json()["result"] == "ignored"
        with SessionLocal() as db:
            assert db.get(Organization, oid).plan_status == "canceled"
            assert db.query(BillingEvent).count() >= 5
    # existing self-hosted orgs (no plan_status) are never gated, even with hosting on
    with TestClient(app) as c:
        c.post("/login", data=dict(csrf=_csrf(c, "/login"), email="admin@coop.test", password="correct-horse-battery"))
        with SessionLocal() as db:
            home = db.query(Organization).order_by(Organization.id).first()
            assert home.plan_status is None
        r = c.post("/assets/new", data=dict(csrf=_csrf(c, "/assets/new"), name="Home Sub Z", asset_type="Substation"))
        assert "Changes are paused" not in r.text
