import io
import os
import re
import tempfile
import zipfile
from datetime import date

os.environ["PRISMCIP_DATA_DIR"] = tempfile.mkdtemp(prefix="prismcip-test-")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.compliance import add_calendar_months_end  # noqa: E402
from app.main import app  # noqa: E402

CSRF = re.compile(r'name="csrf" value="([^"]+)"')


def token(client, url="/"):
    return CSRF.search(client.get(url).text).group(1)


def post(client, url, data=None, files=None, from_url=None, **kw):
    data = dict(data or {})
    data["csrf"] = token(client, from_url or "/")
    return client.post(url, data=data, files=files, follow_redirects=False, **kw)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        c.get("/setup")
        r = c.post("/setup", data=dict(csrf=CSRF.search(c.get("/setup").text).group(1), org_name="Test Co-op",
                                       name="Admin", email="admin@coop.test", password="correct-horse-battery"),
                   follow_redirects=False)
        assert r.status_code == 303
        yield c


def test_calendar_month_math():
    assert add_calendar_months_end(date(2026, 3, 10), 15) == date(2027, 6, 30)
    assert add_calendar_months_end(date(2026, 11, 30), 15) == date(2028, 2, 29)
    assert add_calendar_months_end(date(2026, 1, 1), 36) == date(2029, 1, 31)


def test_csrf_required(client):
    r = client.post("/vendors", data={"name": "NoToken"}, follow_redirects=False)
    assert r.status_code == 400


def test_full_section6_flow(client):
    r = post(client, "/assets/new", dict(name="North Substation", asset_type="Substation",
                                         routable_external="on", vendor_remote_access_allowed="on"),
             from_url="/assets/new")
    assert r.status_code == 303
    asset_id = int(r.headers["location"].rsplit("/", 1)[1])

    # gap: allows vendor access but no paths recorded
    assert "allows vendor remote access but no access paths" in client.get("/requirements").text

    r = post(client, "/vendors", dict(name="Relay Pros LLC"), from_url="/vendors")
    vendor_id = int(r.headers["location"].rsplit("/", 1)[1])
    r = post(client, "/access", dict(vendor_id=vendor_id, asset_id=asset_id, access_method="Client VPN"),
             from_url="/vendors")
    access_id = int(r.headers["location"].rsplit("/", 1)[1])
    page = client.get("/requirements").text
    assert "no method to disable access" in page

    post(client, f"/access/{access_id}", dict(access_method="Client VPN", determine_method="VPN logs reviewed",
                                              disable_method="Disable VPN account", detect_method="IPS on VPN zone"),
         from_url=f"/access/{access_id}")
    assert "no method to disable access" not in client.get("/requirements").text

    post(client, f"/access/{access_id}/sessions", dict(vendor_person="Pat", purpose="Firmware"),
         from_url=f"/access/{access_id}")
    assert "Open vendor sessions" in client.get("/").text and "Pat" in client.get("/").text

    # disabling closes open sessions
    post(client, f"/access/{access_id}/toggle", from_url=f"/access/{access_id}")
    detail = client.get(f"/access/{access_id}").text
    assert "Terminated by entity" in detail and "Re-enable access" in detail
    assert "vendor_access_disabled" in client.get("/activity").text

    # can't log a session on a disabled path
    r = post(client, f"/access/{access_id}/sessions", dict(vendor_person="Sam", purpose="x"),
             from_url=f"/access/{access_id}")
    assert "Sam" not in client.get(f"/access/{access_id}").text


def test_evidence_due_dates_and_export(client):
    reqs = client.get("/requirements").text
    rid = re.search(r'href="/requirements/(\d+)"><b>CIP-003 Att1 S1</b>', reqs).group(1)
    r = post(client, f"/requirements/{rid}/evidence",
             dict(title="Awareness email", performed_on="2025-01-15"),
             files={"file": ("awareness.pdf", io.BytesIO(b"%PDF-1.4 test"), "application/pdf")},
             from_url=f"/requirements/{rid}")
    assert r.status_code == 303
    page = client.get(f"/requirements/{rid}").text
    assert "2026-04-30" in page  # Jan 2025 + 15 calendar months -> end of Apr 2026
    assert "Overdue" in page  # today is after that

    bad = post(client, f"/requirements/{rid}/evidence", dict(title="x", performed_on="2026-01-01"),
               files={"file": ("evil.exe", io.BytesIO(b"MZ"), "application/octet-stream")},
               from_url=f"/requirements/{rid}")
    assert bad.status_code == 303 and client.get(f"/requirements/{rid}").text.count("evil.exe") == 0

    assert "TODO" in client.get("/plan").text

    r = client.get("/export")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    for expected in ("00_summary.html", "01_cip003_low_impact_plan_DRAFT.html", "02_assets.csv",
                     "03_vendor_remote_access.csv", "04_vendor_sessions.csv", "05_evidence_index.csv",
                     "06_activity_log.csv"):
        assert expected in names
    assert any(n.startswith("evidence/CIP-003 Att1 S1/") for n in names)
    assert "North Substation" in z.read("02_assets.csv").decode()


def test_viewer_cannot_edit_and_orgs_are_isolated(client):
    post(client, "/settings/users", dict(email="viewer@coop.test", name="V", role="viewer",
                                         password="viewer-password-123"), from_url="/settings")
    with TestClient(app) as v:
        t = CSRF.search(v.get("/login").text).group(1)
        v.post("/login", data=dict(csrf=t, email="viewer@coop.test", password="viewer-password-123"))
        assert v.get("/").status_code == 200
        r = post(v, "/vendors", dict(name="Should fail"), from_url="/vendors")
        assert r.status_code == 403

    # a second org must not see the first org's records
    from app.auth import hash_password
    from app.db import SessionLocal
    from app.models import Asset, Organization, User
    with SessionLocal() as db:
        org2 = Organization(name="Other Muni")
        db.add(org2)
        db.flush()
        db.add(User(org_id=org2.id, email="other@muni.test", name="O", role="admin",
                    password_hash=hash_password("other-password-123")))
        db.commit()
        first_asset = db.query(Asset).first().id
    with TestClient(app) as o:
        t = CSRF.search(o.get("/login").text).group(1)
        o.post("/login", data=dict(csrf=t, email="other@muni.test", password="other-password-123"))
        assert "North Substation" not in o.get("/assets").text
        assert o.get(f"/assets/{first_asset}").status_code == 404


def test_unauthenticated_redirects():
    with TestClient(app) as anon:
        r = anon.get("/assets", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"
