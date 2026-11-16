"""Backups in Settings. Only platform admins: a backup holds every organization's data."""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import backup
from ..auth import admin, audit, csrf_protect, is_platform_admin
from ..db import get_db
from ..models import User
from ..web import redirect, render

router = APIRouter()


def _guard(db, user):
    if not is_platform_admin(db, user):
        raise HTTPException(403, "Only the platform administrator manages backups.")


@router.get("/settings/backups")
def page(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    _guard(db, user)
    items = [{"name": p.name, "size": p.stat().st_size, "path": p} for p in backup.list_backups()]
    import os
    return render(request, "backups.html", user, items=items, dest=str(backup.BACKUP_DIR),
                  encrypted=bool(os.environ.get("PRISMCIP_BACKUP_PASSPHRASE")),
                  scheduled=os.environ.get("PRISMCIP_BACKUPS", "on") != "off",
                  hour=os.environ.get("PRISMCIP_BACKUP_HOUR", "2"), result=request.session.pop("backup_result", None))


@router.post("/settings/backups", dependencies=[Depends(csrf_protect)])
async def act(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    _guard(db, user)
    f = await request.form()
    if f.get("action") == "verify":
        p = _find(f.get("name", ""))
        try:
            rep = backup.verify(p)
        except backup.BackupError as e:
            rep = {"ok": False, "problems": [str(e)]}
        request.session["backup_result"] = {"name": p.name, **{k: rep.get(k) for k in ("ok", "problems", "files",
                                                                                        "counts")}}
        audit(db, user, "backup_verified", f"{p.name}: {'ok' if rep['ok'] else 'FAILED'}")
        db.commit()
        return redirect("/settings/backups")
    try:
        p = backup.create(label=f"manual by {user.email}")
        rep = backup.verify(p)
    except backup.BackupError as e:
        return redirect("/settings/backups", f"Backup failed: {e}", request)
    audit(db, user, "backup_created", f"{p.name} ({p.stat().st_size:,} bytes), verified {'ok' if rep['ok'] else 'FAILED'}")
    db.commit()
    return redirect("/settings/backups", f"Backup created and verified: {p.name}", request)


def _find(name: str) -> Path:
    for p in backup.list_backups():
        if p.name == name:
            return p
    raise HTTPException(404)


@router.get("/settings/backups/{name}")
def download(name: str, user: User = Depends(admin), db: Session = Depends(get_db)):
    _guard(db, user)
    p = _find(name)
    audit(db, user, "backup_downloaded", p.name)
    db.commit()
    return FileResponse(p, filename=p.name, media_type="application/octet-stream")
