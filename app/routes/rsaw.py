"""RSAW workbook pages and export."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..db import get_db
from ..models import Narrative, Requirement, User, utcnow
from ..rsaw import draft, workbook
from ..web import redirect, render, s, templates

router = APIRouter()


def _save(db, user, code, body):
    key = f"rsaw:{code}"
    n = db.query(Narrative).filter_by(org_id=user.org_id, key=key).first()
    if n is None:
        n = Narrative(org_id=user.org_id, key=key, body=body or "", updated_by=user.email)
        db.add(n)
    n.body, n.updated_by, n.updated_at = body or "", user.email, utcnow()


@router.get("/rsaw")
def rsaw_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ids = {r.code: r.id for r in db.query(Requirement).all()}
    from .. import ai
    return render(request, "rsaw.html", user, ids=ids, ai_on=ai.enabled(user.org),
                  suggestions=ai.pending(db, user.org_id, "rsaw:"), **workbook(db, user.org))


@router.post("/rsaw/{rid}", dependencies=[Depends(csrf_protect)])
async def rsaw_save(rid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    req = db.get(Requirement, rid)
    if not req:
        raise HTTPException(404)
    f = await request.form()
    body = draft(db, user.org, req.code) if f.get("action") == "draft" else (s(f, "body") or "")
    _save(db, user, req.code, body)
    audit(db, user, "rsaw_response_" + ("drafted" if f.get("action") == "draft" else "saved"), req.code)
    db.commit()
    return redirect(f"/rsaw#r{rid}", f"{req.code} response {'drafted from records' if f.get('action') == 'draft' else 'saved'}.",
                    request)


@router.post("/rsaw-draft-all", dependencies=[Depends(csrf_protect)])
def rsaw_draft_all(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    n = 0
    for req in db.query(Requirement).all():
        if not db.query(Narrative).filter_by(org_id=user.org_id, key=f"rsaw:{req.code}").first():
            text = draft(db, user.org, req.code)
            if text:
                _save(db, user, req.code, text)
                n += 1
    audit(db, user, "rsaw_drafted_empty", f"{n} response(s)")
    db.commit()
    return redirect("/rsaw", f"Drafted {n} empty response(s) from your records. Review each before the audit.", request)


@router.get("/rsaw/export")
def rsaw_export(user: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..models import Evidence
    from .evidence import lock_evidence
    html = render_export(db, user.org)
    n = lock_evidence(db.query(Evidence).filter_by(org_id=user.org_id, superseded_by_id=None).all(),
                      f"Listed in RSAW workbook exported {utcnow():%Y-%m-%d}")
    audit(db, user, "rsaw_exported", f"{n} evidence item(s) newly locked")
    db.commit()
    return Response(html, media_type="text/html", headers={
        "Content-Disposition": f'attachment; filename="PrismCIP_RSAW_workbook_{utcnow():%Y-%m-%d}.html"'})


def render_export(db, org) -> str:
    from .reports import evidence_zip_path
    return templates.get_template("rsaw_export.html").render(zip_path=evidence_zip_path, **workbook(db, org))
