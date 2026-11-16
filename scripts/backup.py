"""Backups from the command line.

  python -m scripts.backup create [--dest DIR]
  python -m scripts.backup verify FILE
  python -m scripts.backup restore FILE TARGET_DATA_DIR [--force]
  python -m scripts.backup list

Encrypted backups (.zip.enc) use PRISMCIP_BACKUP_PASSPHRASE, or you're asked for it.
To put a restore live: stop the app, restore into an empty folder, point PRISMCIP_DATA_DIR at it, start the app.
"""
import argparse
import getpass
import os
import sys
from pathlib import Path

from app import backup


def _pass(path: str) -> str | None:
    if path.endswith(".enc") and not os.environ.get("PRISMCIP_BACKUP_PASSPHRASE"):
        return getpass.getpass("Backup passphrase: ")
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m scripts.backup")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--dest")
    v = sub.add_parser("verify")
    v.add_argument("file")
    r = sub.add_parser("restore")
    r.add_argument("file")
    r.add_argument("target")
    r.add_argument("--force", action="store_true")
    sub.add_parser("list")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "create":
            p = backup.create(Path(a.dest) if a.dest else None, label="manual")
            print(f"Created {p} ({p.stat().st_size:,} bytes)")
            print(backup.verify(p))
        elif a.cmd == "verify":
            rep = backup.verify(Path(a.file), _pass(a.file))
            print(rep)
            return 0 if rep["ok"] else 1
        elif a.cmd == "restore":
            rep = backup.restore(Path(a.file), Path(a.target), _pass(a.file), force=a.force)
            print(f"Restored into {a.target}: {rep['files']} files, counts {rep['counts']}")
        else:
            for p in backup.list_backups():
                print(f"{p.name}  {p.stat().st_size:,} bytes")
    except backup.BackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
