"""Session import, approved access windows, findings, and the token-protected ingest API."""
import hashlib
import hmac
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from ..auth import admin, audit, csrf_protect, current_user, editor
from ..db import get_db
from ..ingest import import_text
from ..models import AccessApproval, Finding, ImportBatch, Organization, User, VendorAccess, utcnow
from ..web import dt, redirect, render, s
from .inventory import owned

router = APIRouter()
MAX_LOG_BYTES = 20 * 1024 * 1024


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


# ---------- import ----------
@router.get("/access/import")
def import_form(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .. import syslog
    batches = db.query(ImportBatch).filter_by(org_id=user.org_id).order_by(ImportBatch.id.desc()).limit(25).all()
    unmapped = sum(1 for p in db.query(VendorAccess).filter_by(org_id=user.org_id).all() if not p.account_list)
    return render(request, "import.html", user, batches=batches, unmapped_paths=unmapped, syslog=syslog.stats)


@router.post("/access/import", dependencies=[Depends(csrf_protect)])
async def import_upload(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    up = f.get("file")
    if not isinstance(up, UploadFile) or not up.filename:
        return redirect("/access/import", "Choose a log or CSV file.", request)
    data = await up.read(MAX_LOG_BYTES + 1)
    if len(data) > MAX_LOG_BYTES:
        return redirect("/access/import", "File is larger than 20 MB. Split it or use the API.", request)
    fmt = f.get("format") if f.get("format") in ("auto", "fortigate", "globalprotect", "csv") else "auto"
    try:
        batch, parsed = import_text(db, user.org, _decode(data), by=user.email, fmt=fmt, file_name=up.filename[:300])
    except ValueError as e:
        db.rollback()
        return redirect("/access/import", str(e), request)
    audit(db, user, "sessions_imported",
          f"{up.filename}: {batch.records} records, {batch.sessions_new} new, {batch.sessions_matched} matched, "
          f"{batch.duplicates} duplicates, {batch.findings_new} findings")
    db.commit()
    msg = (f"Imported {batch.records} session(s) from {parsed.lines} line(s): {batch.sessions_new} new, "
           f"{batch.sessions_matched} matched to logged sessions, {batch.duplicates} already imported. "
           f"{batch.findings_new} new finding(s).")
    return redirect("/findings" if batch.findings_new else "/access/import", msg, request)


# ---------- approval windows ----------
@router.post("/access/{pid}/approvals", dependencies=[Depends(csrf_protect)])
async def approval_create(pid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    p = owned(db, VendorAccess, pid, user)
    f = await request.form()
    start, end = dt(f, "starts_at"), dt(f, "ends_at")
    if not start or not end or end <= start or not s(f, "purpose"):
        return redirect(f"/access/{pid}", "An approval window needs a purpose, a start and an end after the start.",
                        request)
    w = AccessApproval(org_id=user.org_id, access_id=p.id, starts_at=start, ends_at=end, purpose=s(f, "purpose"),
                       ticket=s(f, "ticket"), approved_by=s(f, "approved_by") or user.email, status="Approved")
    db.add(w)
    audit(db, user, "access_window_approved",
          f"{p.vendor.name} → {p.asset.name}: {start:%Y-%m-%d %H:%M}–{end:%Y-%m-%d %H:%M} UTC ({w.purpose})")
    db.commit()
    return redirect(f"/access/{pid}", "Access window approved.", request)


@router.post("/approvals/{wid}/decide", dependencies=[Depends(csrf_protect)])
async def approval_decide(wid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    w = owned(db, AccessApproval, wid, user)
    f = await request.form()
    decision = f.get("decision")
    if decision not in ("approve", "deny", "revoke"):
        raise HTTPException(400)
    if decision == "approve" and w.status == "Requested":
        w.status, w.approved_by = "Approved", user.email
    elif decision == "deny" and w.status == "Requested":
        w.status = "Denied"
    elif decision == "revoke" and w.status == "Approved":
        w.status = "Revoked"
        if w.ends_at > utcnow():
            w.ends_at = max(w.starts_at, utcnow())
    else:
        return redirect(f"/access/{w.access_id}", "Nothing to change.", request)
    audit(db, user, f"access_window_{w.status.lower()}", f"{w.access.vendor.name} → {w.access.asset.name}: {w.purpose}")
    db.commit()
    return redirect(f"/access/{w.access_id}", f"Window {w.status.lower()}.", request)


# ---------- findings ----------
@router.get("/findings")
def findings(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    show = request.query_params.get("show", "open")
    q = db.query(Finding).filter_by(org_id=user.org_id)
    if show != "all":
        q = q.filter_by(status="Open")
    order = {"high": 0, "medium": 1, "low": 2}
    rows = sorted(q.all(), key=lambda x: (x.status != "Open", order.get(x.severity, 3), -x.id))
    return render(request, "findings.html", user, rows=rows, show=show)


@router.post("/findings/{fid}/resolve", dependencies=[Depends(csrf_protect)])
async def finding_resolve(fid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    x = owned(db, Finding, fid, user)
    f = await request.form()
    note = s(f, "resolution")
    if not note:
        return redirect("/findings", "Write what was done or why it's acceptable before resolving.", request)
    x.status, x.resolution, x.resolved_by, x.resolved_at = "Resolved", note, user.email, utcnow()
    audit(db, user, "finding_resolved", f"{x.title}: {note}")
    db.commit()
    return redirect("/findings", "Finding resolved.", request)


# ---------- settings for import ----------
@router.post("/settings/ingest", dependencies=[Depends(csrf_protect)])
async def ingest_settings(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    f = await request.form()
    org = user.org
    if f.get("action") == "token":
        tok = "pcip_" + secrets.token_urlsafe(32)
        org.ingest_token_hash = hashlib.sha256(tok.encode()).hexdigest()
        audit(db, user, "ingest_token_rotated")
        db.commit()
        return redirect("/settings", f"New ingest API token (shown once, copy it now): {tok}", request)
    if f.get("action") == "revoke":
        org.ingest_token_hash = None
        audit(db, user, "ingest_token_revoked")
        db.commit()
        return redirect("/settings", "Ingest API token revoked.", request)
    org.ignored_accounts = s(f, "ignored_accounts")
    audit(db, user, "ignored_accounts_updated")
    db.commit()
    return redirect("/settings", "Ignored accounts saved.", request)


# ---------- API ----------
@router.post("/api/v1/sessions")
async def api_ingest(request: Request, db: Session = Depends(get_db)):
    """Push raw FortiGate logs or CSV. Auth: Authorization: Bearer <ingest token>. Optional ?format=fortigate|csv"""
    auth = request.headers.get("authorization", "")
    tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not tok:
        return JSONResponse({"error": "missing bearer token"}, status_code=401)
    digest = hashlib.sha256(tok.encode()).hexdigest()
    org = next((o for o in db.query(Organization).filter(Organization.ingest_token_hash.isnot(None)).all()
                if hmac.compare_digest(o.ingest_token_hash, digest)), None)
    if not org:
        return JSONResponse({"error": "invalid token"}, status_code=401)
    body = await request.body()
    if len(body) > MAX_LOG_BYTES:
        return JSONResponse({"error": "body larger than 20 MB"}, status_code=413)
    fmt = request.query_params.get("format", "auto")
    fmt = fmt if fmt in ("auto", "fortigate", "globalprotect", "csv") else "auto"
    try:
        batch, parsed = import_text(db, org, _decode(body), by="api", fmt=fmt, source="api")
    except ValueError as e:
        db.rollback()
        return JSONResponse({"error": str(e)}, status_code=400)
    from ..models import AuditLog
    db.add(AuditLog(org_id=org.id, actor="api", action="sessions_imported",
                    detail=f"{batch.records} records, {batch.sessions_new} new, {batch.findings_new} findings"))
    db.commit()
    return {"lines": parsed.lines, "skipped": parsed.skipped, "records": batch.records, "new": batch.sessions_new,
            "matched": batch.sessions_matched, "duplicates": batch.duplicates, "findings": batch.findings_new}
