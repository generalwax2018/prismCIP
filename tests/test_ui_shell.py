"""The page shell matches RiskPrism: glass toolbar, grouped sidebar, light and dark, nothing loaded from outside."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # importing test_app first points the app at a throwaway data folder
from app.main import app

CSS = (Path(__file__).resolve().parent.parent / "app" / "static" / "style.css").read_text(encoding="utf-8")


def test_follows_system_light_and_dark():
    assert "@media (prefers-color-scheme: dark)" in CSS
    assert "color-scheme: light" in CSS and "color-scheme: dark" in CSS


def test_readable_without_backdrop_blur():
    assert "@supports not ((backdrop-filter: blur(1px))" in CSS


def test_loads_nothing_from_outside():
    assert "@import" not in CSS
    assert not re.search(r"url\(\s*['\"]?(https?:)?//", CSS)


def test_braces_balance():
    assert CSS.count("{") == CSS.count("}")


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        if "/setup" in str(c.get("/login").url):
            c.post("/setup", data=dict(csrf=CSRF.search(c.get("/setup").text).group(1), org_name="Shell Co-op",
                                       name="Admin", email="admin@coop.test", password="correct-horse-battery"))
        else:
            c.post("/login", data=dict(csrf=CSRF.search(c.get("/login").text).group(1), email="admin@coop.test",
                                       password="correct-horse-battery"))
        yield c


def test_every_view_marks_itself_once(admin):
    client = admin
    for path, label in (("/", "Dashboard"), ("/requirements", "Requirements"), ("/access", "Remote access"),
                        ("/plan", "Plan"), ("/assets", "Assets"), ("/vendors", "Vendors"),
                        ("/activity", "Activity log"), ("/settings", "Settings"),
                        ("/programs/awareness", "Awareness"), ("/programs/exercise", "IR exercises"),
                        ("/programs/transient", "Transient devices"), ("/signoffs", "Sign-offs"), ("/rsaw", "RSAW workbook"),
                        ("/findings", "Findings"), ("/noncompliance", "Noncompliance"),
                        ("/audit-requests", "Audit requests"), ("/reports/board", "Board report"), ("/readiness", "CIP-003-11 readiness"),
                        ("/access/review", "Account review")):
        page = client.get(path).text
        on = re.findall(r'<a class="on" href="([^"]*)">', page)
        assert on == [path], (path, on)
        assert label in page
        assert 'class="topbar"' in page and 'class="rail"' in page
        assert '<meta name="color-scheme" content="light dark">' in page
        for tag in re.findall(r"<(?:link|script|img)\b[^>]*>", page):
            assert not re.search(r'(src|href)="(https?:)?//', tag), tag


def test_sign_in_page_has_no_shell():
    with TestClient(app) as anon:
        page = anon.get("/login").text
        assert 'class="login"' in page and 'class="rail"' not in page and "login-card" in page
