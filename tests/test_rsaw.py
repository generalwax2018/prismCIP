import io
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app.db import SessionLocal
from app.main import app
from app.models import Narrative, Requirement

PW = "correct-horse-battery"


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as c:
        if "/setup" in str(c.get("/login").url):
            c.post("/setup", data=dict(csrf=CSRF.search(c.get("/setup").text).group(1), org_name="RSAW Co-op",
                                       name="Admin", email="admin@coop.test", password=PW))
        else:
            c.post("/login", data=dict(csrf=CSRF.search(c.get("/login").text).group(1), email="admin@coop.test",
                                       password=PW))
        yield c


def post(c, url, data=None, page="/rsaw"):
    data = dict(data or {})
    data["csrf"] = CSRF.search(c.get(page).text).group(1)
    return c.post(url, data=data, follow_redirects=False)


def test_workbook_lists_every_requirement(c):
    page = c.get("/rsaw").text
    for code in ("CIP-002 R1.3", "CIP-002 R2", "CIP-003 R1.2", "CIP-003 Att1 S6.1", "CIP-003 Att1 S6.3",
                 "CIP-003 R3", "CIP-003 R4"):
        assert code in page
    assert "Auditor looks for" in page


def test_draft_and_save_response(c):
    with SessionLocal() as db:
        rid = db.query(Requirement).filter_by(code="CIP-003 Att1 S6.1").first().id
    post(c, f"/rsaw/{rid}", dict(action="draft"))
    with SessionLocal() as db:
        n = db.query(Narrative).filter_by(key="rsaw:CIP-003 Att1 S6.1").first()
        assert n and "vendor" in n.body.lower()
    post(c, f"/rsaw/{rid}", dict(action="save", body="Our own words."))
    with SessionLocal() as db:
        assert db.query(Narrative).filter_by(key="rsaw:CIP-003 Att1 S6.1").first().body == "Our own words."
    r = post(c, "/rsaw-draft-all")
    with SessionLocal() as db:
        assert db.query(Narrative).filter_by(key="rsaw:CIP-003 Att1 S6.1").first().body == "Our own words."
        assert db.query(Narrative).filter(Narrative.key.like("rsaw:%")).count() >= 10


def test_export_and_audit_package_links_match(c):
    r = c.get("/rsaw/export")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "Our own words." in r.text
    z = zipfile.ZipFile(io.BytesIO(c.get("/export").content))
    names = set(z.namelist())
    assert {"07_rsaw_workbook.html", "08_signoffs.csv", "09_findings.csv"} <= names
    workbook = z.read("07_rsaw_workbook.html").decode()
    for href in re.findall(r'href="(evidence/[^"]+)"', workbook):
        href = href.replace("&#39;", "'").replace("&amp;", "&")
        assert href in names, href
