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
    allev = (db.query(Evidence).filter_by(org_id=user.org_id, requirement_id=rid)
             .order_by(Evidence.performed_on.desc()).all())
    ev = [e for e in allev if not e.superseded_by_id]
    replaced = [e for e in allev if e.superseded_by_id]
    assets = db.query(Asset).filter_by(org_id=user.org_id).order_by(Asset.name).all()
    from ..compliance import NA_ALLOWED
    return render(request, "requirement_detail.html", user, req=req, st=st, evidence=ev, replaced=replaced,
                  assets=assets, na_allowed=NA_ALLOWED.get(req.code))


def lock_evidence(items, reason: str) -> int:
    """Lock evidence so it can only be superseded from now on. Returns how many were newly locked."""
    from ..models import utcnow
    n = 0
    for e in items:
        if not e.locked_at:
            e.locked_at, e.locked_reason = utcnow(), reason[:300]
            n += 1
    return n


@router.post("/requirements/{rid}/na", dependencies=[Depends(csrf_protect)])
async def mark_na(rid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    from ..compliance import NA_ALLOWED
    from ..models import Applicability, utcnow
    from ..web import templates
    req = db.get(Requirement, rid)
    if not req or req.code not in NA_ALLOWED:
        raise HTTPException(400, "This requirement can't be marked not applicable.")
    f = await request.form()
    reason = s(f, "reason")
    if not reason or len(reason) < 15:
        return redirect(f"/requirements/{rid}", "Explain why it doesn't apply (a sentence or two). Auditors read this.",
                        request)
    if db.query(Applicability).filter_by(org_id=user.org_id, requirement_id=rid, withdrawn_at=None).first():
        return redirect(f"/requirements/{rid}", "Already marked not applicable.", request)
    now = utcnow()
    record = templates.get_template("na_record.html").render(req=req, org=user.org, reason=reason, by=user, at=now)
    data = record.encode()
    org_dir = UPLOAD_DIR / str(user.org_id)
    org_dir.mkdir(parents=True, exist_ok=True)
    stored = f"{uuid.uuid4().hex}.html"
    (org_dir / stored).write_bytes(data)
    ev = Evidence(org_id=user.org_id, requirement_id=rid, title=f"Not applicable: {req.code}", description=reason,
                  performed_on=now.date(), file_name=f"not_applicable_{req.code.replace(' ', '_')}.html",
                  stored_name=stored, sha256=hashlib.sha256(data).hexdigest(), uploaded_by=user.email,
                  locked_at=now, locked_reason="Applicability decision record")
    db.add(ev)
    db.flush()
    db.add(Applicability(org_id=user.org_id, requirement_id=rid, reason=reason, decided_by=user.email,
                         decided_at=now, evidence_id=ev.id))
    audit(db, user, "marked_not_applicable", f"{req.code}: {reason}")
    db.commit()
    return redirect(f"/requirements/{rid}", "Marked not applicable. The reason is filed as evidence.", request)


@router.post("/requirements/{rid}/na/withdraw", dependencies=[Depends(csrf_protect)])
async def withdraw_na(rid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    from ..models import Applicability, utcnow
    a = db.query(Applicability).filter_by(org_id=user.org_id, requirement_id=rid, withdrawn_at=None).first()
    if a:
        a.withdrawn_at, a.withdrawn_by = utcnow(), user.email
        audit(db, user, "not_applicable_withdrawn", a.requirement.code)
        db.commit()
    return redirect(f"/requirements/{rid}", "Not-applicable withdrawn. The requirement applies again.", request)


@router.post("/evidence/{eid}/supersede", dependencies=[Depends(csrf_protect)])
async def supersede(eid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    from ..models import utcnow
    old = db.get(Evidence, eid)
    if not old or old.org_id != user.org_id:
        raise HTTPException(404)
    if old.superseded_by_id:
        return redirect(f"/requirements/{old.requirement_id}", "That item was already replaced.", request)
    f = await request.form()
    note, title, when = s(f, "note"), s(f, "title") or old.title, d(f, "performed_on") or old.performed_on
    if not note:
        return redirect(f"/requirements/{old.requirement_id}", "Say why it's being replaced.", request)
    fileinfo, err = await store_upload(f.get("file"), user.org_id)
    if err:
        return redirect(f"/requirements/{old.requirement_id}", err, request)
    new = Evidence(org_id=user.org_id, requirement_id=old.requirement_id, asset_id=old.asset_id, title=title,
                   description=s(f, "description") or old.description, performed_on=when, uploaded_by=user.email,
                   **(fileinfo or {}))
    db.add(new)
    db.flush()
    old.superseded_by_id, old.superseded_at, old.superseded_note = new.id, utcnow(), note
    audit(db, user, "evidence_superseded", f"{old.requirement.code}: #{old.id} '{old.title}' → #{new.id} '{new.title}'"
                                           f" ({note})")
    db.commit()
    return redirect(f"/requirements/{old.requirement_id}", "Replaced. The earlier version is kept and marked "
                                                           "superseded.", request)


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
    if ev.locked_at:
        return redirect(f"/requirements/{rid}", f"Locked ({ev.locked_reason}). Replace it with a newer version instead "
                                                f"of deleting it.", request)
    if db.query(Evidence).filter_by(superseded_by_id=ev.id).first():
        return redirect(f"/requirements/{rid}", "This item replaced an earlier version, so it's kept. Replace it "
                                                "instead.", request)
    audit(db, user, "evidence_deleted", f"{ev.requirement.code}: {ev.title}"
          + (f" sha256={ev.sha256}" if ev.sha256 else ""))
    if ev.stored_name and evidence_path(ev).exists():
        evidence_path(ev).unlink()
    db.delete(ev)
    db.commit()
    return redirect(f"/requirements/{rid}", "Evidence deleted (recorded in the activity log).", request)
