"""Audit request tracker: each evidence request from the Regional Entity, its owner, deadline, response and files."""
import io
import zipfile
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..db import get_db
from ..models import AuditRequest, Evidence, Requirement, User, utcnow
from ..web import d, redirect, render, s, templates
from .evidence import evidence_path, lock_evidence
from .inventory import owned
from .reports import _safe

router = APIRouter()
STATUSES = ["Open", "In progress", "Submitted", "Closed"]


@router.get("/audit-requests")
def ar_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(AuditRequest).filter_by(org_id=user.org_id).order_by(AuditRequest.due_on).all()
    rows.sort(key=lambda r: (r.status in ("Submitted", "Closed"), r.due_on))
    from ..members import member_users
    users = member_users(db, user.org_id, active_only=True)
    reqs = db.query(Requirement).order_by(Requirement.sort_order).all()
    n = db.query(AuditRequest).filter_by(org_id=user.org_id).count()
    return render(request, "audit_requests.html", user, rows=rows, users=users, reqs=reqs, today=date.today(),
                  next_ref=f"RFI-{n + 1:02d}")


@router.post("/audit-requests", dependencies=[Depends(csrf_protect)])
async def ar_create(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    if not s(f, "ref") or not s(f, "request") or not d(f, "received_on") or not d(f, "due_on"):
        return redirect("/audit-requests", "Needs a reference, the request text, and received and due dates.", request)
    owner = None
    if s(f, "owner_id"):
        from ..members import membership
        o = db.get(User, int(f["owner_id"]))
        owner = o.id if o and membership(db, o.id, user.org_id) else None
    req = db.get(Requirement, int(f["requirement_id"])) if s(f, "requirement_id") else None
    r = AuditRequest(org_id=user.org_id, ref=s(f, "ref")[:40], request=s(f, "request"), received_on=d(f, "received_on"),
                     due_on=d(f, "due_on"), owner_id=owner, requirement_id=req.id if req else None,
                     created_by=user.email)
    db.add(r)
    db.flush()
    audit(db, user, "audit_request_logged", f"{r.ref} due {r.due_on}")
    db.commit()
    if owner and owner != user.id:
        from .. import mailer
        o = db.get(User, owner)
        try:
            mailer.send([o.email], f"PrismCIP: audit request {r.ref} assigned to you (due {r.due_on})",
                        f"{r.ref}: {r.request}\n\nDue {r.due_on}. Open it in PrismCIP → Audit requests.")
        except Exception as exc:
            print(f"[prismcip] assignment email failed: {exc!r}")
    return redirect(f"/audit-requests/{r.id}", "Request logged.", request)


@router.get("/audit-requests/{aid}")
def ar_detail(aid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    r = owned(db, AuditRequest, aid, user)
    q = db.query(Evidence).filter_by(org_id=user.org_id, superseded_by_id=None)
    if r.requirement_id and request.query_params.get("all") != "1":
        q = q.filter_by(requirement_id=r.requirement_id)
    candidates = [e for e in q.order_by(Evidence.performed_on.desc()).all() if e not in r.evidence]
    from ..members import member_users
    users = member_users(db, user.org_id, active_only=True)
    return render(request, "audit_request_detail.html", user, r=r, candidates=candidates, users=users,
                  statuses=STATUSES, today=date.today())


@router.post("/audit-requests/{aid}", dependencies=[Depends(csrf_protect)])
async def ar_update(aid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    r = owned(db, AuditRequest, aid, user)
    f = await request.form()
    action = f.get("action")
    if action == "link":
        for eid in f.getlist("evidence_id"):
            e = db.get(Evidence, int(eid))
            if e and e.org_id == user.org_id and e not in r.evidence:
                r.evidence.append(e)
        if r.status == "Open":
            r.status = "In progress"
        audit(db, user, "audit_request_evidence_linked", f"{r.ref}: {len(f.getlist('evidence_id'))} item(s)")
    elif action == "unlink" and r.status not in ("Submitted", "Closed"):
        e = db.get(Evidence, int(f.get("evidence_id", 0)))
        if e in r.evidence:
            r.evidence.remove(e)
    elif action == "submit":
        if not (r.response or s(f, "response")):
            return redirect(f"/audit-requests/{aid}", "Write the response before marking it submitted.", request)
        r.response = s(f, "response") or r.response
        r.status, r.submitted_on = "Submitted", d(f, "submitted_on") or utcnow().date()
        n = lock_evidence(r.evidence, f"Submitted in audit response {r.ref}")
        audit(db, user, "audit_request_submitted", f"{r.ref}: {len(r.evidence)} file(s), {n} newly locked")
    elif action == "close":
        r.status = "Closed"
        audit(db, user, "audit_request_closed", r.ref)
    else:
        r.response = s(f, "response")
        if s(f, "owner_id"):
            from ..members import membership
            o = db.get(User, int(f["owner_id"]))
            r.owner_id = o.id if o and membership(db, o.id, user.org_id) else r.owner_id
        r.due_on = d(f, "due_on") or r.due_on
        if r.status == "Open" and r.response:
            r.status = "In progress"
        audit(db, user, "audit_request_updated", r.ref)
    db.commit()
    return redirect(f"/audit-requests/{aid}", "Saved.", request)


@router.get("/audit-requests/{aid}/package")
def ar_package(aid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """The response and its files, ready to upload to the Regional Entity's portal."""
    r = owned(db, AuditRequest, aid, user)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        files = []
        for e in r.evidence:
            name = ""
            if e.stored_name and evidence_path(e).exists():
                name = f"{e.id}_{_safe(e.file_name or 'file')}"
                z.write(evidence_path(e), name)
            files.append((e, name))
        z.writestr("response.html", templates.get_template("audit_response.html").render(r=r, org=user.org,
                                                                                         files=files))
    audit(db, user, "audit_request_package_downloaded", r.ref)
    db.commit()
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{_safe(r.ref)}_response.zip"'})
