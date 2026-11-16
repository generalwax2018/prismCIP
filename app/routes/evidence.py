"""Requirement tracker and evidence uploads."""
import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.datastructures import UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..compliance import requirement_statuses
from ..db import UPLOAD_DIR, get_db
from ..models import Asset, Evidence, Requirement, User
from ..web import d, redirect, render, s

router = APIRouter()
MAX_BYTES = 50 * 1024 * 1024
ALLOWED = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".txt", ".log", ".csv", ".json", ".xml", ".docx", ".xlsx",
           ".pptx", ".doc", ".xls", ".msg", ".eml", ".zip", ".md", ".html", ".cfg", ".conf"}


@router.get("/requirements")
def requirements(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "requirements.html", user, statuses=requirement_statuses(db, user.org))


@router.get("/requirements/{rid}")
def requirement_detail(rid: int, request: Request, user: User = Depends(current_user),
                       db: Session = Depends(get_db)):
    req = db.get(Requirement, rid)
    if not req:
        raise HTTPException(404)
    st = next(x for x in requirement_statuses(db, user.org) if x.req.id == rid)
    ev = (db.query(Evidence).filter_by(org_id=user.org_id, requirement_id=rid)
          .order_by(Evidence.performed_on.desc()).all())
    assets = db.query(Asset).filter_by(org_id=user.org_id).order_by(Asset.name).all()
    return render(request, "requirement_detail.html", user, req=req, st=st, evidence=ev, assets=assets)


@router.post("/requirements/{rid}/evidence", dependencies=[Depends(csrf_protect)])
async def add_evidence(rid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    req = db.get(Requirement, rid)
    if not req:
        raise HTTPException(404)
    f = await request.form()
    title, performed_on = s(f, "title"), d(f, "performed_on")
    if not title or not performed_on:
        return redirect(f"/requirements/{rid}", "Evidence needs a title and the date it was performed.", request)
    asset_id = None
    if s(f, "asset_id"):
        a = db.get(Asset, int(f["asset_id"]))
        if a and a.org_id == user.org_id:
            asset_id = a.id
    ev = Evidence(org_id=user.org_id, requirement_id=rid, asset_id=asset_id, title=title,
                  description=s(f, "description"), performed_on=performed_on, uploaded_by=user.email)
    upload = f.get("file")
    if isinstance(upload, UploadFile) and upload.filename:
        ext = Path(upload.filename).suffix.lower()
        if ext not in ALLOWED:
            return redirect(f"/requirements/{rid}", f"File type {ext or '(none)'} isn't allowed.", request)
        data = await upload.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return redirect(f"/requirements/{rid}", "File is larger than 50 MB.", request)
        org_dir = UPLOAD_DIR / str(user.org_id)
        org_dir.mkdir(parents=True, exist_ok=True)
        stored = f"{uuid.uuid4().hex}{ext}"
        (org_dir / stored).write_bytes(data)
        ev.file_name = Path(upload.filename).name[:300]
        ev.stored_name = stored
        ev.sha256 = hashlib.sha256(data).hexdigest()
    db.add(ev)
    audit(db, user, "evidence_added", f"{req.code}: {title}" + (f" [{ev.file_name} sha256={ev.sha256[:12]}…]"
                                                                 if ev.sha256 else ""))
    db.commit()
    return redirect(f"/requirements/{rid}", "Evidence added.", request)


async def store_upload(upload, org_id: int) -> tuple[dict | None, str | None]:
    """Save an uploaded evidence file. Returns (fields for Evidence, error message)."""
    if not isinstance(upload, UploadFile) or not upload.filename:
        return None, None
    ext = Path(upload.filename).suffix.lower()
    if ext not in ALLOWED:
        return None, f"File type {ext or '(none)'} isn't allowed."
    data = await upload.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        return None, "File is larger than 50 MB."
    org_dir = UPLOAD_DIR / str(org_id)
    org_dir.mkdir(parents=True, exist_ok=True)
    stored = f"{uuid.uuid4().hex}{ext}"
    (org_dir / stored).write_bytes(data)
    return dict(file_name=Path(upload.filename).name[:300], stored_name=stored,
                sha256=hashlib.sha256(data).hexdigest()), None


def evidence_path(ev: Evidence) -> Path:
    return UPLOAD_DIR / str(ev.org_id) / ev.stored_name


@router.get("/evidence/{eid}/download")
def download(eid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ev = db.get(Evidence, eid)
    if not ev or ev.org_id != user.org_id or not ev.stored_name or not evidence_path(ev).exists():
        raise HTTPException(404)
    return FileResponse(evidence_path(ev), filename=ev.file_name, media_type="application/octet-stream")


@router.post("/evidence/{eid}/delete", dependencies=[Depends(csrf_protect)])
def delete_evidence(eid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    ev = db.get(Evidence, eid)
    if not ev or ev.org_id != user.org_id:
        raise HTTPException(404)
    rid = ev.requirement_id
    audit(db, user, "evidence_deleted", f"{ev.requirement.code}: {ev.title}"
          + (f" sha256={ev.sha256}" if ev.sha256 else ""))
    if ev.stored_name and evidence_path(ev).exists():
        evidence_path(ev).unlink()
    db.delete(ev)
    db.commit()
    return redirect(f"/requirements/{rid}", "Evidence deleted (recorded in the activity log).", request)
