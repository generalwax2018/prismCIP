import io
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401  (throwaway data folder)
from app.db import SessionLocal
from app.ingest import parse_csv, parse_fortigate
from app.main import app
from app.models import AccessApproval, AccessSession, Finding, Organization
from datetime import datetime

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_fortigate_pairs_up_and_down_and_skips_noise():
    r = parse_fortigate((SAMPLES / "fortigate_vpn_events.log").read_text())
    assert r.lines == 9 and r.skipped == 2  # ssl-web duplicate + IPsec negotiate
    first = r.records[0]
    assert first.account == "relaypros-jalvarez" and first.source_ip == "203.0.113.24"
    assert first.started_at == datetime(2026, 11, 2, 15, 1, 12)  # 08:01:12 at -0700 -> UTC
    assert first.ended_at == datetime(2026, 11, 2, 16, 47, 40)
    assert len({x.key for x in r.records}) == len(r.records)


def test_fortigate_down_without_up_uses_duration():
    line = ('date=2026-11-12 time=14:05:00 tz="+0000" logid="0101039948" type="event" subtype="vpn" '
            'action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=9 user="v1" remip=1.2.3.4 duration=600')
    rec = parse_fortigate(line).records[0]
    assert rec.started_at == datetime(2026, 11, 12, 13, 55) and rec.ended_at == datetime(2026, 11, 12, 14, 5)


def test_ipsec_dialup_xauthuser():
    line = ('date=2026-11-12 time=10:00:00 tz="+0000" logid="0101037138" type="event" subtype="vpn" '
            'action="tunnel-up" tunneltype="ipsec" tunnelid=77 remip=5.6.7.8 xauthuser="vendor-x"')
    assert parse_fortigate(line).records[0].account == "vendor-x"


def test_csv_detects_columns_and_rejects_unknown_layout():
    r = parse_csv((SAMPLES / "remote_support_sessions.csv").read_text())
    assert [x.account for x in r.records] == ["oem-noc", "oem-noc"]
    with pytest.raises(ValueError):
        parse_csv("a,b\n1,2\n")


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        if "/setup" in str(c.get("/login").url):
            c.post("/setup", data=dict(csrf=CSRF.search(c.get("/setup").text).group(1), org_name="Ingest Co-op",
                                       name="Admin", email="admin@coop.test", password="correct-horse-battery"))
        else:
            c.post("/login", data=dict(csrf=CSRF.search(c.get("/login").text).group(1), email="admin@coop.test",
                                       password="correct-horse-battery"))
        yield c


def _post(c, url, data=None, files=None, page="/"):
    data = dict(data or {})
    data["csrf"] = CSRF.search(c.get(page).text).group(1)
    return c.post(url, data=data, files=files, follow_redirects=False)


def test_import_reconciles_against_approvals(admin):
    c = admin
    a = _post(c, "/assets/new", dict(name="Ingest Sub", asset_type="Substation", vendor_remote_access_allowed="on"),
              page="/assets/new")
    aid = int(a.headers["location"].rsplit("/", 1)[1])
    v = _post(c, "/vendors", dict(name="Relay Pros (ingest)"), page="/vendors")
    vid = int(v.headers["location"].rsplit("/", 1)[1])
    p = _post(c, "/access", dict(vendor_id=vid, asset_id=aid, access_method="Client VPN"), page="/vendors")
    pid = int(p.headers["location"].rsplit("/", 1)[1])
    _post(c, f"/access/{pid}", dict(access_method="Client VPN", accounts="relaypros-jalvarez"), page=f"/access/{pid}")
    _post(c, f"/access/{pid}/approvals", dict(starts_at="2026-11-02T14:30", ends_at="2026-11-02T18:00",
                                              purpose="Firmware"), page=f"/access/{pid}")
    _post(c, "/settings/ingest", dict(ignored_accounts="it-admin"), page="/settings")

    log = (SAMPLES / "fortigate_vpn_events.log").read_bytes()
    r = _post(c, "/access/import", dict(format="auto"), files={"file": ("vpn.log", io.BytesIO(log), "text/plain")},
              page="/access/import")
    assert r.status_code == 303
    with SessionLocal() as db:
        sessions = db.query(AccessSession).filter_by(access_id=pid).order_by(AccessSession.started_at).all()
        assert len(sessions) == 2
        assert sessions[0].approval_id is not None and sessions[1].approval_id is None
        kinds = sorted(f.kind for f in db.query(Finding).filter_by(status="Open").all())
        assert "unapproved" in kinds and "unmapped_account" in kinds
        assert not any("it-admin" in (f.title or "") for f in db.query(Finding).all())  # ignored staff account

    # re-importing the same file creates nothing new
    r = _post(c, "/access/import", dict(format="fortigate"), files={"file": ("vpn.log", io.BytesIO(log), "text/plain")},
              page="/access/import")
    with SessionLocal() as db:
        assert db.query(AccessSession).filter_by(access_id=pid).count() == 2

    # the unapproved session shows up as a gap and in the nav badge
    assert "Open finding" in c.get("/requirements").text
    assert re.search(r'Findings<span class="badge" data-n="[1-9]', c.get("/").text)

    # resolve needs a note
    with SessionLocal() as db:
        fid = db.query(Finding).filter_by(kind="unapproved", status="Open").first().id
    _post(c, f"/findings/{fid}/resolve", dict(resolution=""), page="/findings")
    with SessionLocal() as db:
        assert db.get(Finding, fid).status == "Open"
    _post(c, f"/findings/{fid}/resolve", dict(resolution="Emergency call-out, approved by phone, CHG-4502"),
          page="/findings")
    with SessionLocal() as db:
        assert db.get(Finding, fid).status == "Resolved"


def test_manual_session_is_confirmed_not_duplicated(admin):
    c = admin
    from app.models import Vendor, VendorAccess
    with SessionLocal() as db:
        pid = (db.query(VendorAccess).join(Vendor).filter(Vendor.name == "Relay Pros (ingest)").first().id)
    _post(c, f"/access/{pid}/sessions", dict(vendor_person="J. Alvarez", purpose="Settings check",
                                             started_at="2026-11-20T10:00"), page=f"/access/{pid}")
    log = ('date=2026-11-20 time=10:12:00 tz="+0000" logid="0101039947" type="event" subtype="vpn" '
           'action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=5 user="relaypros-jalvarez" remip=203.0.113.24\n'
           'date=2026-11-20 time=11:00:00 tz="+0000" logid="0101039948" type="event" subtype="vpn" '
           'action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=5 user="relaypros-jalvarez" remip=203.0.113.24')
    before = None
    with SessionLocal() as db:
        before = db.query(AccessSession).filter_by(access_id=pid).count()
    _post(c, "/access/import", files={"file": ("x.log", io.BytesIO(log.encode()), "text/plain")}, page="/access/import")
    with SessionLocal() as db:
        assert db.query(AccessSession).filter_by(access_id=pid).count() == before
        s = db.query(AccessSession).filter_by(access_id=pid, vendor_person="J. Alvarez").first()
        assert s.external_key and s.ended_at is not None and s.source_ip == "203.0.113.24"


def test_api_requires_token_and_imports(admin):
    c = admin
    assert c.post("/api/v1/sessions", content=b"x").status_code == 401
    assert c.post("/api/v1/sessions", content=b"x", headers={"Authorization": "Bearer nope"}).status_code == 401
    r = _post(c, "/settings/ingest", dict(action="token"), page="/settings")
    tok = re.search(r"pcip_[\w-]+", c.get("/settings").text).group(0)
    csv_body = (SAMPLES / "remote_support_sessions.csv").read_bytes()
    r = c.post("/api/v1/sessions?format=csv", content=csv_body, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json()["records"] == 2
    _post(c, "/settings/ingest", dict(action="revoke"), page="/settings")
    assert c.post("/api/v1/sessions", content=csv_body, headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_vendor_portal_request_and_approval(admin):
    c = admin
    from app.models import Vendor, VendorAccess
    with SessionLocal() as db:
        v = db.query(Vendor).filter_by(name="Relay Pros (ingest)").first()
        vid, pid = v.id, v.access[0].id
    _post(c, f"/vendors/{vid}/portal", page=f"/vendors/{vid}")
    link = re.search(r"/portal/([\w-]+)", c.get(f"/vendors/{vid}").text).group(1)
    with TestClient(app) as vendor:  # not signed in
        page = vendor.get(f"/portal/{link}")
        assert page.status_code == 200 and "Ingest Sub" in page.text and "Relay Pros (ingest)" in page.text
        assert "rail" not in page.text  # no app shell for vendors
        t = CSRF.search(page.text).group(1)
        vendor.post(f"/portal/{link}", data=dict(csrf=t, access_id=pid, person="J. Alvarez", purpose="Firmware",
                                                 starts_at="2026-12-01T15:00", ends_at="2026-12-01T18:00"))
        with SessionLocal() as db:  # terms not accepted -> nothing saved
            assert db.query(AccessApproval).filter_by(status="Requested").count() == 0
        vendor.post(f"/portal/{link}", data=dict(csrf=t, access_id=pid, person="J. Alvarez", purpose="Firmware",
                                                 starts_at="2026-12-01T15:00", ends_at="2026-12-01T18:00", terms="on"))
        assert vendor.get("/portal/not-a-real-token").status_code == 404
        assert vendor.get("/").status_code in (200, 303) and "/login" in str(vendor.get("/").url)
    with SessionLocal() as db:
        w = db.query(AccessApproval).filter_by(status="Requested").first()
        assert w and w.requested_by == "J. Alvarez"
    assert "Waiting on you" in c.get("/").text
    _post(c, f"/approvals/{w.id}/decide", dict(decision="approve"), page=f"/access/{pid}")
    with SessionLocal() as db:
        assert db.get(AccessApproval, w.id).status == "Approved"
    _post(c, f"/vendors/{vid}/portal", dict(action="revoke"), page=f"/vendors/{vid}")
    with TestClient(app) as vendor:
        assert vendor.get(f"/portal/{link}").status_code == 404


def test_globalprotect_parse_times_and_skips():
    r = parse_csv  # noqa: F841  (keep import used)
    from app.ingest import parse_globalprotect
    res = parse_globalprotect((SAMPLES / "globalprotect_events.log").read_text())
    assert res.lines == 5 and res.skipped == 2  # portal-auth and a failed connect
    first = res.records[0]
    assert first.account == "scada-integrator" and first.started_at == datetime(2026, 11, 3, 16, 0)
    assert first.ended_at == datetime(2026, 11, 3, 17, 30)


def test_panos_rule_review_and_dtd_refusal():
    from app.fwreview import parse_any, review
    brand, rules = parse_any((SAMPLES / "panos_running_config.xml").read_text())
    issues = review(rules)
    assert brand == "PAN-OS" and sum(i.severity == "high" for i in issues) == 1
    assert not any("SCADA-to-RTU" in i.rule for i in issues) and not any("old-disabled" in i.rule for i in issues)
    evil = ('<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x "y">]><config><rulebase><security><rules>'
            '</rules></security></rulebase></config>')
    with pytest.raises(ValueError):
        parse_any(evil)


def test_syslog_cross_batch_pairing_and_sender_filter():
    from app import syslog
    from app.models import Vendor, VendorAccess
    sources = syslog.parse_sources("10.9.9.9, 10.8.0.0/16")
    with SessionLocal() as db:
        path = db.query(VendorAccess).join(Vendor).filter(Vendor.name == "Relay Pros (ingest)").first()
        org_id, pid = path.org_id, path.id
        before = db.query(AccessSession).filter_by(access_id=pid).count()
    up = ('date=2026-12-02 time=15:00:00 tz="+0000" logid="0101039947" type="event" subtype="vpn" '
          'action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=777 user="relaypros-jalvarez" remip=203.0.113.24')
    down = ('date=2026-12-02 time=15:40:00 tz="+0000" logid="0101039948" type="event" subtype="vpn" '
            'action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=777 user="relaypros-jalvarez" '
            'remip=203.0.113.24 duration=2400')
    syslog.accept("192.0.2.1", up, sources, org_id)  # not a listed sender
    syslog.accept("10.8.3.4", "some unrelated firewall traffic log", sources, org_id)
    assert syslog.stats["dropped_sender"] >= 1 and syslog.stats["irrelevant"] >= 1
    syslog.accept("10.9.9.9", up, sources, org_id)
    syslog.flush()
    with SessionLocal() as db:
        s = db.query(AccessSession).filter_by(access_id=pid).order_by(AccessSession.id.desc()).first()
        assert s.ended_at is None and db.query(AccessSession).filter_by(access_id=pid).count() == before + 1
    syslog.accept("10.8.1.1", down, sources, org_id)  # the end arrives later, from another listed sender
    syslog.flush()
    with SessionLocal() as db:
        assert db.query(AccessSession).filter_by(access_id=pid).count() == before + 1  # closed, not duplicated
        s = db.get(AccessSession, s.id)
        assert s.ended_at == datetime(2026, 12, 2, 15, 40)


@pytest.mark.skipif("postgres" in __import__("os").environ.get("PRISMCIP_DATABASE_URL", ""), reason="copies the SQLite install")
def test_live_udp_listener_end_to_end(tmp_path):
    import os
    import socket
    import sqlite3
    import subprocess
    import sys
    import time
    import urllib.request
    from app import backup
    data = tmp_path / "data"
    backup.restore(backup.create(tmp_path, passphrase=""), data, passphrase="")  # a copy of the test install
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    web = s.getsockname()[1]
    s.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 0))
    sport = u.getsockname()[1]
    u.close()
    con = sqlite3.connect(data / "prismcip.db")
    org_id = con.execute("SELECT org_id FROM vendor_access WHERE accounts LIKE '%relaypros-jalvarez%'").fetchone()[0]
    con.close()
    env = dict(os.environ, PRISMCIP_DATA_DIR=str(data), PRISMCIP_SYSLOG_PORT=str(sport),
               PRISMCIP_SYSLOG_HOST="127.0.0.1", PRISMCIP_SYSLOG_SOURCES=f"127.0.0.1={org_id}",
               PRISMCIP_REMINDERS="off", PRISMCIP_BACKUPS="off")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(web)],
                            cwd=SAMPLES.parent, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{web}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        line = ('<190>date=2026-12-09 time=03:00:00 tz="+0000" logid="0101039947" type="event" subtype="vpn" '
                'action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=4242 user="relaypros-jalvarez" '
                'remip=198.51.100.200')
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.sendto(line.encode(), ("127.0.0.1", sport))
        c.close()
        found = None
        for _ in range(40):
            time.sleep(0.5)
            con = sqlite3.connect(data / "prismcip.db")
            found = con.execute("SELECT source_ip FROM access_sessions WHERE source_ip='198.51.100.200'").fetchone()
            nf = con.execute("SELECT count(*) FROM findings WHERE detail LIKE '%198.51.100.200%'").fetchone()[0]
            con.close()
            if found:
                break
        assert found and nf == 1  # arrived live, and it's unapproved so it became a finding
    finally:
        proc.terminate()
        proc.wait(timeout=10)
