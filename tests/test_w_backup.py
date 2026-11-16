"""Backups: create, verify, detect tampering, encrypt, restore into an empty folder, and boot the app on it."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_app import CSRF  # noqa: F401
from app import backup
from app.db import DATA_DIR, SessionLocal
from app.main import app
from app.models import Evidence

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(not backup._sqlite_path(), reason="file backups hold the SQLite DB; Postgres installs use pg_dump")


def test_create_verify_and_tamper_detection(tmp_path):
    p = backup.create(tmp_path, passphrase="")
    rep = backup.verify(p, passphrase="")
    assert rep["ok"], rep["problems"]
    assert rep["counts"]["evidence"] >= 1 and rep["database"] == "sqlite"
    # change one byte of one evidence file inside the archive -> verify must fail
    bad = tmp_path / "tampered.zip"
    with zipfile.ZipFile(p) as zin, zipfile.ZipFile(bad, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.startswith("evidence/") and data:
                data = bytes([data[0] ^ 1]) + data[1:]
                hit = item.filename
            zout.writestr(item, data)
    rep = backup.verify(bad, passphrase="")
    assert not rep["ok"] and any("hash mismatch" in x for x in rep["problems"])
    with pytest.raises(backup.BackupError):
        backup.restore(bad, tmp_path / "nope", passphrase="")


def test_encrypted_backup_needs_passphrase(tmp_path):
    p = backup.create(tmp_path, passphrase="correct horse")
    assert p.name.endswith(".zip.enc")
    with pytest.raises(backup.BackupError):
        backup.verify(p, passphrase="wrong horse")
    assert backup.verify(p, passphrase="correct horse")["ok"]


def test_retention_keeps_recent_and_monthly(tmp_path):
    start = datetime(2024, 1, 1)
    for i in range(0, 900, 3):  # a backup every 3 days for ~2.5 years
        stamp = (start + timedelta(days=i)).strftime("%Y%m%d-020000")
        (tmp_path / f"prismcip-backup-{stamp}.zip").write_bytes(b"x")
    backup.prune(tmp_path)
    left = backup.list_backups(tmp_path)
    months = {p.name[16:22] for p in left}
    assert len(left) <= backup.KEEP_RECENT + backup.KEEP_MONTHS
    assert len(months) >= 29  # one per month kept back to the start


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_restore_boots_and_signs_in(tmp_path):
    p = backup.create(tmp_path, passphrase="")
    target = tmp_path / "restored"
    backup.restore(p, target, passphrase="")
    with pytest.raises(backup.BackupError):  # never over an existing install without force
        backup.restore(p, target, passphrase="")
    with SessionLocal() as db:  # restored evidence files match the originals byte for byte
        for e in db.query(Evidence).filter(Evidence.stored_name.isnot(None)).all():
            src = DATA_DIR / "evidence" / str(e.org_id) / e.stored_name
            dst = target / "evidence" / str(e.org_id) / e.stored_name
            assert dst.read_bytes() == src.read_bytes()
    port = _free_port()
    env = dict(os.environ, PRISMCIP_DATA_DIR=str(target), PRISMCIP_REMINDERS="off", PRISMCIP_BACKUPS="off")
    env.pop("PRISMCIP_DATABASE_URL", None)
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        import http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        page = opener.open(f"http://127.0.0.1:{port}/login").read().decode()
        tok = CSRF.search(page).group(1)
        data = f"csrf={tok}&email=admin%40coop.test&password=correct-horse-battery".encode()
        resp = opener.open(f"http://127.0.0.1:{port}/login", data=data)
        assert "/login" not in resp.geturl() or "Compliance dashboard" in resp.read().decode()
        dash = opener.open(f"http://127.0.0.1:{port}/").read().decode()
        assert "Compliance dashboard" in dash and "North Substation" in opener.open(
            f"http://127.0.0.1:{port}/assets").read().decode()
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_backup_page_is_platform_admin_only(monkeypatch):
    with TestClient(app) as c:
        c.post("/login", data=dict(csrf=CSRF.search(c.get("/login").text).group(1), email="admin@coop.test",
                                   password="correct-horse-battery"))
        # several organizations exist in the test DB, so an org admin isn't a platform admin by default
        assert c.get("/settings/backups").status_code == 403
        monkeypatch.setenv("PRISMCIP_PLATFORM_ADMINS", "admin@coop.test")
        monkeypatch.setattr(backup, "BACKUP_DIR", Path(tempfile.mkdtemp()))
        assert c.get("/settings/backups").status_code == 200
        r = c.post("/settings/backups", data=dict(csrf=CSRF.search(c.get("/settings/backups").text).group(1)))
        assert "Backup created and verified" in r.text
