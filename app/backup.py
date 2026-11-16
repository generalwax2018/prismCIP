"""Backups: a consistent database snapshot, every evidence file, and a manifest of SHA-256 hashes.

* Safe while the app runs: SQLite is copied with its online backup API, not by copying the file.
* Verifiable: verify() checks every file against the manifest and runs SQLite's integrity check.
* Restorable: restore() only proceeds after a successful verify, and only into an empty data folder unless forced.
* Optional encryption: set PRISMCIP_BACKUP_PASSPHRASE and backups are written as .zip.enc (scrypt-derived keys,
  SHAKE-256 keystream, HMAC-SHA256 tag checked before anything is decrypted). Keep the passphrase off the server.
* Retention: the 14 most recent backups, plus the newest one in each of the last 36 calendar months.

Postgres installs: the database is not in the file backup (use pg_dump / your managed backups); evidence still is.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import shutil
import sqlite3
import struct
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .db import DATA_DIR, DATABASE_URL, UPLOAD_DIR

BACKUP_DIR = Path(os.environ.get("PRISMCIP_BACKUP_DIR", DATA_DIR / "backups"))
KEEP_RECENT, KEEP_MONTHS = 14, 36
MAGIC = b"PCIPBK1\n"
CHUNK = 1024 * 1024


class BackupError(Exception):
    pass


def _sqlite_path() -> Path | None:
    if DATABASE_URL.startswith("sqlite:///"):
        return Path(DATABASE_URL[len("sqlite:///"):])
    return None


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- optional encryption (standard library only) ----------
def _keys(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    root = hashlib.scrypt(passphrase.encode(), salt=salt, n=2**15, r=8, p=1, dklen=64, maxmem=64 * 1024 * 1024)
    return root[:32], root[32:]


def _stream(enc_key: bytes, nonce: bytes, index: int, length: int = CHUNK) -> bytes:
    return hashlib.shake_256(enc_key + nonce + struct.pack(">Q", index)).digest(length)


def _xor(data: bytes, ks: bytes) -> bytes:
    n = len(data)
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks[:n], "big")).to_bytes(n, "big")


def encrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    salt, nonce = os.urandom(16), os.urandom(16)
    enc, mac_key = _keys(passphrase, salt)
    mac = hmac.new(mac_key, MAGIC + salt + nonce, hashlib.sha256)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(MAGIC + salt + nonce)
        idx = 0
        for chunk in iter(lambda: fi.read(CHUNK), b""):
            ct = _xor(chunk, _stream(enc, nonce, idx, len(chunk)))
            mac.update(ct)
            fo.write(ct)
            idx += 1
        fo.write(mac.digest())


def decrypt_file(src: Path, dst: Path, passphrase: str) -> None:
    data_len = src.stat().st_size - len(MAGIC) - 32 - 32
    if data_len < 0:
        raise BackupError("Encrypted backup is truncated.")
    with open(src, "rb") as fi:
        head = fi.read(len(MAGIC) + 32)
        if not head.startswith(MAGIC):
            raise BackupError("Not a PrismCIP encrypted backup.")
        salt, nonce = head[len(MAGIC):len(MAGIC) + 16], head[len(MAGIC) + 16:]
        enc, mac_key = _keys(passphrase, salt)
        mac = hmac.new(mac_key, head, hashlib.sha256)
        remaining = data_len
        while remaining > 0:  # authenticate before decrypting anything
            chunk = fi.read(min(CHUNK, remaining))
            mac.update(chunk)
            remaining -= len(chunk)
        if not hmac.compare_digest(mac.digest(), fi.read(32)):
            raise BackupError("Wrong passphrase, or the backup was altered.")
        fi.seek(len(head))
        remaining, idx = data_len, 0
        with open(dst, "wb") as fo:
            while remaining > 0:
                chunk = fi.read(min(CHUNK, remaining))
                fo.write(_xor(chunk, _stream(enc, nonce, idx, len(chunk))))
                remaining -= len(chunk)
                idx += 1


# ---------- create ----------
def create(dest_dir: Path | None = None, passphrase: str | None = None, label: str = "scheduled") -> Path:
    dest_dir = Path(dest_dir or BACKUP_DIR)
    dest_dir.mkdir(parents=True, exist_ok=True)
    passphrase = passphrase if passphrase is not None else os.environ.get("PRISMCIP_BACKUP_PASSPHRASE") or None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    manifest = {"format": 1, "created_utc": stamp, "label": label, "files": {}, "database": "none"}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        zpath = tmp / f"prismcip-backup-{stamp}.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
            db_path = _sqlite_path()
            if db_path and db_path.exists():
                snap = tmp / "prismcip.db"
                src = sqlite3.connect(str(db_path))
                dst = sqlite3.connect(str(snap))
                with dst:
                    src.backup(dst)
                src.close()
                ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
                counts = {t: dst.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                          for t in ("organizations", "users", "evidence", "audit_log")
                          if dst.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()}
                dst.close()
                if ok != "ok":
                    raise BackupError(f"Database integrity check failed before backup: {ok}")
                z.write(snap, "db/prismcip.db")
                manifest["files"]["db/prismcip.db"] = {"sha256": _sha(snap), "size": snap.stat().st_size}
                manifest["database"], manifest["counts"] = "sqlite", counts
            else:
                manifest["database"] = "external (back it up with your database tooling)"
            anchors = DATA_DIR / "chain_anchors.log"
            if anchors.exists():  # activity-log anchors live outside the database on purpose
                z.write(anchors, "chain_anchors.log")
                manifest["files"]["chain_anchors.log"] = {"sha256": _sha(anchors), "size": anchors.stat().st_size}
            key = DATA_DIR / ".secret_key"
            if key.exists():  # needed to read two-step sign-in secrets after a restore
                z.write(key, "secret_key")
                manifest["files"]["secret_key"] = {"sha256": _sha(key), "size": key.stat().st_size}
            for f in sorted(UPLOAD_DIR.rglob("*")):
                if f.is_file():
                    arc = "evidence/" + f.relative_to(UPLOAD_DIR).as_posix()
                    z.write(f, arc)
                    manifest["files"][arc] = {"sha256": _sha(f), "size": f.stat().st_size}
            z.writestr("manifest.json", json.dumps(manifest, indent=1))
        if passphrase:
            out = dest_dir / (zpath.name + ".enc")
            encrypt_file(zpath, out, passphrase)
        else:
            out = dest_dir / zpath.name
            shutil.copyfile(zpath, out)
    try:
        out.chmod(0o600)
    except OSError:
        pass
    prune(dest_dir)
    return out


# ---------- verify / restore ----------
def _open_zip(path: Path, passphrase: str | None, tmp: Path) -> Path:
    if path.suffix == ".enc":
        if not passphrase:
            raise BackupError("This backup is encrypted; the passphrase is needed.")
        plain = tmp / path.stem
        decrypt_file(path, plain, passphrase)
        return plain
    return path


def verify(path: Path, passphrase: str | None = None) -> dict:
    path = Path(path)
    passphrase = passphrase if passphrase is not None else os.environ.get("PRISMCIP_BACKUP_PASSPHRASE") or None
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        zpath = _open_zip(path, passphrase, tmp)
        try:
            z = zipfile.ZipFile(zpath)
        except zipfile.BadZipFile as exc:
            raise BackupError(f"Not a valid backup archive: {exc}") from exc
        with z:
            if "manifest.json" not in z.namelist():
                raise BackupError("Backup has no manifest.")
            manifest = json.loads(z.read("manifest.json"))
            problems = []
            names = set(z.namelist())
            for arc, meta in manifest["files"].items():
                if arc not in names:
                    problems.append(f"missing {arc}")
                    continue
                h = hashlib.sha256()
                with z.open(arc) as fh:
                    for chunk in iter(lambda: fh.read(CHUNK), b""):
                        h.update(chunk)
                if h.hexdigest() != meta["sha256"]:
                    problems.append(f"hash mismatch {arc}")
            extra = names - set(manifest["files"]) - {"manifest.json"}
            if extra:
                problems.append(f"unexpected files: {sorted(extra)[:5]}")
            if "db/prismcip.db" in names and not problems:
                z.extract("db/prismcip.db", tmp)
                con = sqlite3.connect(str(tmp / "db" / "prismcip.db"))
                ok = con.execute("PRAGMA integrity_check").fetchone()[0]
                if ok != "ok":
                    problems.append(f"database integrity: {ok}")
                else:  # every evidence file the database references must be in the backup
                    for org_id, stored in con.execute(
                            "SELECT org_id, stored_name FROM evidence WHERE stored_name IS NOT NULL").fetchall():
                        if f"evidence/{org_id}/{stored}" not in names:
                            problems.append(f"evidence file missing for org {org_id}: {stored}")
                con.close()
    return {"ok": not problems, "problems": problems, "created_utc": manifest.get("created_utc"),
            "files": len(manifest["files"]), "counts": manifest.get("counts", {}),
            "database": manifest.get("database")}


def restore(path: Path, target_dir: Path, passphrase: str | None = None, force: bool = False) -> dict:
    """Restore into target_dir (a PrismCIP data folder). Refuses a non-empty folder unless force=True."""
    path, target_dir = Path(path), Path(target_dir)
    report = verify(path, passphrase)
    if not report["ok"]:
        raise BackupError("Backup failed verification; not restoring: " + "; ".join(report["problems"][:5]))
    if target_dir.exists() and any(p for p in target_dir.iterdir() if p.name != "backups") and not force:
        raise BackupError(f"{target_dir} isn't empty. Restore into an empty folder, or pass force.")
    target_dir.mkdir(parents=True, exist_ok=True)
    passphrase = passphrase if passphrase is not None else os.environ.get("PRISMCIP_BACKUP_PASSPHRASE") or None
    with tempfile.TemporaryDirectory() as tmp:
        zpath = _open_zip(path, passphrase, Path(tmp))
        with zipfile.ZipFile(zpath) as z:
            for arc in z.namelist():
                if arc == "manifest.json":
                    continue
                if ".." in Path(arc).parts or arc.startswith("/"):
                    raise BackupError(f"Unsafe path in backup: {arc}")
                if arc == "db/prismcip.db":
                    dest = target_dir / "prismcip.db"
                elif arc == "secret_key":
                    dest = target_dir / ".secret_key"
                elif arc == "chain_anchors.log":
                    dest = target_dir / "chain_anchors.log"
                else:
                    dest = target_dir / arc  # evidence/...
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(arc) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
    for stale in ("prismcip.db-wal", "prismcip.db-shm"):
        (target_dir / stale).unlink(missing_ok=True)
    return report


# ---------- retention ----------
def list_backups(dest_dir: Path | None = None) -> list[Path]:
    d = Path(dest_dir or BACKUP_DIR)
    if not d.exists():
        return []
    return sorted([p for p in d.iterdir() if p.name.startswith("prismcip-backup-") and
                   (p.suffix == ".zip" or p.name.endswith(".zip.enc"))], key=lambda p: p.name, reverse=True)


def prune(dest_dir: Path | None = None) -> list[Path]:
    items = list_backups(dest_dir)
    keep = set(items[:KEEP_RECENT])
    months = {}
    for p in items:  # newest first: first seen per month wins
        month = p.name[len("prismcip-backup-"):][:6]
        months.setdefault(month, p)
    for month in sorted(months, reverse=True)[:KEEP_MONTHS]:
        keep.add(months[month])
    removed = [p for p in items if p not in keep]
    for p in removed:
        p.unlink(missing_ok=True)
    return removed


def latest_info(dest_dir: Path | None = None) -> dict | None:
    items = list_backups(dest_dir)
    if not items:
        return None
    p = items[0]
    return {"name": p.name, "size": p.stat().st_size,
            "at": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).replace(tzinfo=None)}
