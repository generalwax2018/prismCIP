import io
import os
os.environ.setdefault("PRISMCIP_REMINDERS", "off")
os.environ.setdefault("PRISMCIP_BACKUPS", "off")
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
                                         password="temp-Kq83-x7Lm-pz"), from_url="/settings")
    with TestClient(app) as v:
        t = CSRF.search(v.get("/login").text).group(1)
        v.post("/login", data=dict(csrf=t, email="viewer@coop.test", password="temp-Kq83-x7Lm-pz"))
        r = v.get("/", follow_redirects=False)
        assert r.headers["location"] == "/account/password"  # temporary password must be changed first
        t = CSRF.search(v.get("/account/password").text).group(1)
        v.post("/account/password", data=dict(csrf=t, current_password="temp-Kq83-x7Lm-pz",
                                              new_password="blue harbor lantern", confirm="blue harbor lantern"))
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


def test_plan_editor_fills_todos(client):
    before = client.get("/plan").text.count('class="todo"')
    r = post(client, "/plan/edit", dict(s1_method="Annual awareness bulletin every March.",
                                        s4_plan_ref="IR Plan v3 on SharePoint"), from_url="/plan/edit")
    assert r.status_code == 303
    page = client.get("/plan").text
    assert "Annual awareness bulletin every March." in page and "IR Plan v3 on SharePoint" in page
    assert page.count('class="todo"') == before - 2


def test_program_trackers_file_evidence_and_s46_clock(client):
    import re as _re
    from app.db import SessionLocal
    from app.models import Evidence, ProgramRecord
    r = post(client, "/programs/awareness", dict(title="Awareness bulletin", performed_on="2026-03-02",
                                                 method="Email bulletin", audience="All staff"),
             from_url="/programs/awareness")
    assert r.status_code == 303
    post(client, "/programs/exercise", dict(title="Ransomware tabletop", performed_on="2026-01-10", method="Tabletop",
                                            audience="GM, IT"), from_url="/programs/exercise")
    reqs = client.get("/requirements").text
    assert "after the 2026-01-10 test is due by 2026-07-09" in reqs
    with SessionLocal() as db:
        rid = db.query(ProgramRecord).filter_by(kind="exercise").first().id
    post(client, f"/programs/exercise/{rid}/plan-updated", dict(plan_updated_on="2026-02-20",
                                                                 note="Added E-ISAC contact"), from_url="/programs/exercise")
    assert "after the 2026-01-10 test is due" not in client.get("/requirements").text
    post(client, "/programs/transient", dict(title="Vendor laptop", performed_on="2026-04-01",
                                             device_owner="Vendor-managed TCA", result="Malware found"),
         from_url="/programs/transient")
    assert "Malicious code found on a transient device" in client.get("/findings").text
    with SessionLocal() as db:
        codes = {e.requirement.code for e in db.query(Evidence).all()}
    assert {"CIP-003 Att1 S1", "CIP-003 Att1 S4.5", "CIP-003 Att1 S4.6", "CIP-003 Att1 S5"} <= codes


def test_firewall_review_files_evidence_and_findings(client):
    from pathlib import Path
    from app.db import SessionLocal
    from app.fwreview import parse_fortigate_policies, review
    from app.models import Asset, Evidence, Finding
    cfg = (Path(__file__).resolve().parent.parent / "samples" / "fortigate_north_sub.conf").read_bytes()
    issues = review(parse_fortigate_policies(cfg.decode()))
    assert sum(i.severity == "high" for i in issues) == 1
    assert not any(i.rule.startswith("Policy 1 ") for i in issues)  # justified DNP3 rule is clean
    assert not any("Policy 4" in i.rule or "Policy 5" in i.rule for i in issues)  # disabled and deny skipped
    with SessionLocal() as db:
        aid = db.query(Asset).filter_by(name="North Substation").first().id
    r = client.post(f"/assets/{aid}/firewall", data=dict(csrf=CSRF.search(client.get(f"/assets/{aid}").text).group(1)),
                    files={"file": ("fgt.conf", io.BytesIO(cfg), "text/plain")})
    assert r.status_code == 200 and "Firewall rule review" in r.text
    with SessionLocal() as db:
        assert db.query(Evidence).filter(Evidence.title.like("Firewall rule review%")).count() == 1
        assert db.query(Finding).filter_by(kind="firewall_rule").count() == 1
    bad = client.post(f"/assets/{aid}/firewall", data=dict(csrf=CSRF.search(client.get(f"/assets/{aid}").text).group(1)),
                      files={"file": ("x.conf", io.BytesIO(b"hostname router\n"), "text/plain")},
                      follow_redirects=False)
    assert bad.status_code == 303


def test_not_applicable_with_reason_and_contradiction(client):
    from app.db import SessionLocal
    from app.models import Applicability, Asset, Evidence, Requirement
    with SessionLocal() as db:
        rid = db.query(Requirement).filter_by(code="CIP-003 Att1 S3.2").first().id
        r12 = db.query(Requirement).filter_by(code="CIP-003 R1.2").first().id
    post(client, f"/requirements/{rid}/na", dict(reason="short"), from_url=f"/requirements/{rid}")
    with SessionLocal() as db:
        assert not db.query(Applicability).filter_by(requirement_id=rid).count()
    assert client.post(f"/requirements/{r12}/na", data=dict(csrf=CSRF.search(client.get("/").text).group(1),
                                                            reason="We don't think so at all")).status_code == 400
    post(client, f"/requirements/{rid}/na", dict(reason="No asset has dial-up; all RTUs are on fiber."),
         from_url=f"/requirements/{rid}")
    page = client.get(f"/requirements/{rid}").text
    assert "Not applicable" in page and "No asset has dial-up" in page
    with SessionLocal() as db:
        ev = db.query(Evidence).filter_by(requirement_id=rid, title="Not applicable: CIP-003 Att1 S3.2").first()
        assert ev and ev.locked_at
        a = db.query(Asset).first()
        a.dialup = True
        db.commit()
    assert "Marked N/A, but" in client.get(f"/requirements/{rid}").text  # records contradict the decision
    with SessionLocal() as db:
        a = db.query(Asset).first()
        a.dialup = False
        db.commit()
    post(client, f"/requirements/{rid}/na/withdraw", from_url=f"/requirements/{rid}")
    assert "Doesn't apply to you?" in client.get(f"/requirements/{rid}").text


def test_exported_evidence_is_locked_and_can_only_be_replaced(client):
    from app.db import SessionLocal
    from app.models import Evidence
    client.get("/export")
    with SessionLocal() as db:
        e = db.query(Evidence).filter(Evidence.locked_at.isnot(None), Evidence.superseded_by_id.is_(None),
                                      Evidence.title == "Awareness email").first()
        eid, rid = e.id, e.requirement_id
    r = post(client, f"/evidence/{eid}/delete", from_url=f"/requirements/{rid}")
    with SessionLocal() as db:
        assert db.get(Evidence, eid) is not None  # not deleted
    post(client, f"/evidence/{eid}/supersede", dict(note="Wrong year in the title", title="Awareness email 2025"),
         from_url=f"/requirements/{rid}")
    with SessionLocal() as db:
        old = db.get(Evidence, eid)
        assert old.superseded_by_id and old.superseded_note == "Wrong year in the title"
        assert db.get(Evidence, old.superseded_by_id).title == "Awareness email 2025"
    page = client.get(f"/requirements/{rid}").text
    assert "replaced version(s)" in page
    z = zipfile.ZipFile(io.BytesIO(client.get("/export").content))
    idx = z.read("05_evidence_index.csv").decode()
    assert "superseded by #" in idx  # the earlier version stays in the package, marked


def test_noncompliance_log_from_finding_and_close_rules(client):
    from app.db import SessionLocal
    from app.models import Finding, Noncompliance, Requirement
    with SessionLocal() as db:
        fnd = db.query(Finding).first()
        fid = fnd.id
        rid = db.query(Requirement).filter_by(code="CIP-003 Att1 S6.1").first().id
    page = client.get(f"/noncompliance?finding={fid}").text
    assert "From finding" in page
    r = post(client, "/noncompliance", dict(requirement_id=rid, title="Unapproved vendor session",
                                            description="Vendor connected without an approved window.",
                                            discovered_on="2026-11-10", discovered_how="PrismCIP finding",
                                            finding_id=fid), from_url="/noncompliance")
    nid = int(r.headers["location"].rsplit("/", 1)[1])
    post(client, f"/noncompliance/{nid}/status", dict(action="close"), from_url=f"/noncompliance/{nid}")
    with SessionLocal() as db:
        assert db.get(Noncompliance, nid).status == "Open"  # can't close without cause, risk, end date, decision
    post(client, f"/noncompliance/{nid}/steps", dict(text="Disable VPN account between windows", owner="IT",
                                                     due_on="2026-11-20"), from_url=f"/noncompliance/{nid}")
    post(client, f"/noncompliance/{nid}", dict(title="Unapproved vendor session", ended_on="2026-11-10",
                                               started_on="2026-11-09", cause_category="Process",
                                               root_cause="Vendor account left enabled after a job", risk="Minimal",
                                               risk_rationale="Single relay, monitored", disposition="Self-logged"),
         from_url=f"/noncompliance/{nid}")
    with SessionLocal() as db:
        step = db.get(Noncompliance, nid).steps[0].id
    post(client, f"/noncompliance/{nid}/steps", dict(complete=step), from_url=f"/noncompliance/{nid}")
    post(client, f"/noncompliance/{nid}/status", dict(action="close"), from_url=f"/noncompliance/{nid}")
    with SessionLocal() as db:
        x = db.get(Noncompliance, nid)
        assert x.status == "Closed" and x.closed_on
    z = zipfile.ZipFile(io.BytesIO(client.get("/export").content))
    assert "Unapproved vendor session" in z.read("11_noncompliance.csv").decode()


def test_audit_request_tracker_locks_what_was_sent(client):
    from app.db import SessionLocal
    from app.models import AuditRequest, Evidence, Requirement
    with SessionLocal() as db:
        rid = db.query(Requirement).filter_by(code="CIP-003 Att1 S1").first().id
        e = db.query(Evidence).filter_by(requirement_id=rid, superseded_by_id=None).first()
        e.locked_at = None
        db.commit()
        eid = e.id
    r = post(client, "/audit-requests", dict(ref="RFI-01", request="Provide security awareness evidence.",
                                             received_on="2026-11-01", due_on="2026-11-05", requirement_id=rid),
             from_url="/audit-requests")
    aid = int(r.headers["location"].rsplit("/", 1)[1])
    assert "Overdue" in client.get("/audit-requests").text
    client.post(f"/audit-requests/{aid}", data={"csrf": CSRF.search(client.get(f"/audit-requests/{aid}").text).group(1),
                                               "action": "link", "evidence_id": [str(eid)]})
    post(client, f"/audit-requests/{aid}", dict(action="submit", response="Attached: 2025 bulletin."),
         from_url=f"/audit-requests/{aid}")
    with SessionLocal() as db:
        r = db.get(AuditRequest, aid)
        assert r.status == "Submitted" and [x.id for x in r.evidence] == [eid]
        assert db.get(Evidence, eid).locked_at is not None
    pkg = zipfile.ZipFile(io.BytesIO(client.get(f"/audit-requests/{aid}/package").content))
    assert "response.html" in pkg.namelist() and "Attached: 2025 bulletin." in pkg.read("response.html").decode()


def test_vendor_offboarding_and_account_review(client):
    from app.db import SessionLocal
    from app.models import AccountReview, Evidence, Vendor, VendorAccess
    r = post(client, "/vendors", dict(name="Old Integrator"), from_url="/vendors")
    vid = int(r.headers["location"].rsplit("/", 1)[1])
    with SessionLocal() as db:
        from app.models import Asset
        aid = db.query(Asset).filter_by(name="North Substation").first().id
    r = post(client, "/access", dict(vendor_id=vid, asset_id=aid, access_method="Client VPN"), from_url="/vendors")
    pid = int(r.headers["location"].rsplit("/", 1)[1])
    post(client, f"/access/{pid}", dict(access_method="Client VPN", accounts="oldint-a, oldint-b"),
         from_url=f"/access/{pid}")
    # account review: remove one account
    post(client, "/access/review", dict(action="start"), from_url="/access/review")
    with SessionLocal() as db:
        rv = db.query(AccountReview).filter_by(completed_at=None).first()
        decisions = {f"decision_{it.id}": ("remove" if it.account == "oldint-b" else "keep") for it in rv.items}
    r = post(client, "/access/review", dict(action="complete", **decisions), from_url="/access/review")
    with SessionLocal() as db:
        assert db.get(VendorAccess, pid).account_list == ["oldint-a"]
        assert db.query(Evidence).filter_by(title="Vendor account review").count() == 1
    # offboarding can't complete until everything passes
    post(client, f"/vendors/{vid}/offboard", dict(action="start"), from_url=f"/vendors/{vid}/offboard")
    post(client, f"/vendors/{vid}/offboard", dict(action="complete"), from_url=f"/vendors/{vid}/offboard")
    with SessionLocal() as db:
        assert db.get(Vendor, vid).status == "Offboarding"
    post(client, f"/vendors/{vid}/offboard", dict(action="disable_all"), from_url=f"/vendors/{vid}/offboard")
    for key in ("accounts_deleted", "shared_secrets", "devices_returned", "physical_access"):
        post(client, f"/vendors/{vid}/offboard", dict(action="step", key=key), from_url=f"/vendors/{vid}/offboard")
    post(client, f"/vendors/{vid}/offboard", dict(action="complete"), from_url=f"/vendors/{vid}/offboard")
    with SessionLocal() as db:
        v = db.get(Vendor, vid)
        assert v.status == "Offboarded" and db.get(VendorAccess, pid).status == "Disabled"
        ev = db.query(Evidence).filter_by(title="Vendor offboarded: Old Integrator").first()
        assert ev and ev.locked_at


def test_board_report(client):
    page = client.get("/reports/board").text
    assert "board summary" in page and "obligations in good shape" in page and "Vendor remote access" in page
    r = client.get("/reports/board/download")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "<style>" in r.text
