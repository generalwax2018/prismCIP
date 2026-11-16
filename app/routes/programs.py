"""Attachment 1 program trackers: security awareness (S1), incident response exercises (S4.5 / S4.6), and
transient cyber assets and removable media (S5). Every record is also filed as evidence."""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..db import get_db
from ..models import Asset, Evidence, ProgramRecord, Requirement, User
from ..web import d, redirect, render, s
from .evidence import store_upload

router = APIRouter()
KINDS = {
    "awareness": dict(code="CIP-003 Att1 S1", title="Security awareness",
                      blurb="Section 1: reinforce cyber security practices at least once every 15 calendar months. "
                            "Log each bulletin, briefing or poster campaign with who it reached."),
    "exercise": dict(code="CIP-003 Att1 S4.5", title="Incident response exercises",
                     blurb="Section 4.5: test each incident response plan at least once every 36 calendar months. "
                           "Section 4.6: update the plan, if needed, within 180 days afterwards."),
    "transient": dict(code="CIP-003 Att1 S5", title="Transient devices and removable media",
                      blurb="Section 5: record each laptop, vendor device or USB drive checked for malicious code "
                            "before it touched a low impact BCS."),
}
METHODS = {"awareness": ["Email bulletin", "Briefing / toolbox talk", "Posters", "Training module", "Other"],
           "exercise": ["Tabletop", "Drill", "Actual Reportable Cyber Security Incident"],
           "transient": []}


def _req(db, code):
    return db.query(Requirement).filter_by(code=code).first()


@router.get("/programs/{kind}")
def program(kind: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if kind not in KINDS:
        raise HTTPException(404)
    rows = (db.query(ProgramRecord).filter_by(org_id=user.org_id, kind=kind)
            .order_by(ProgramRecord.performed_on.desc()).all())
    assets = db.query(Asset).filter_by(org_id=user.org_id).order_by(Asset.name).all()
    return render(request, "program.html", user, kind=kind, meta=KINDS[kind], rows=rows, assets=assets,
                  methods=METHODS[kind], timedelta=timedelta)


@router.post("/programs/{kind}", dependencies=[Depends(csrf_protect)])
async def program_add(kind: str, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    if kind not in KINDS:
        raise HTTPException(404)
    f = await request.form()
    when, title = d(f, "performed_on"), s(f, "title")
    if not when or not title:
        return redirect(f"/programs/{kind}", "Needs a title and the date it happened.", request)
    asset_id = None
    if s(f, "asset_id"):
        a = db.get(Asset, int(f["asset_id"]))
        asset_id = a.id if a and a.org_id == user.org_id else None
    rec = ProgramRecord(org_id=user.org_id, kind=kind, performed_on=when, title=title, method=s(f, "method"),
                        audience=s(f, "audience"), details=s(f, "details"), device_owner=s(f, "device_owner"),
                        result=s(f, "result"), asset_id=asset_id, created_by=user.email)
    fileinfo, err = await store_upload(f.get("file"), user.org_id)
    if err:
        return redirect(f"/programs/{kind}", err, request)
    desc = {"awareness": f"{rec.method or 'Awareness'}; reached: {rec.audience or 'not recorded'}.",
            "exercise": f"{rec.method or 'Exercise'}; participants: {rec.audience or 'not recorded'}. "
                        f"{rec.details or ''}",
            "transient": f"{rec.device_owner or 'Device'}; result: {rec.result or 'not recorded'}. "
                         f"{rec.details or ''}"}[kind].strip()
    ev = Evidence(org_id=user.org_id, requirement_id=_req(db, KINDS[kind]["code"]).id, asset_id=asset_id,
                  title=title, description=desc, performed_on=when, uploaded_by=user.email, **(fileinfo or {}))
    db.add(ev)
    db.flush()
    rec.evidence_id = ev.id
    db.add(rec)
    if kind == "transient" and rec.result == "Malware found":
        from ..models import Finding
        db.add(Finding(org_id=user.org_id, kind="malware_transient", severity="high",
                       title=f"Malicious code found on a transient device: {title}",
                       detail=rec.details or "", requirement_code="CIP-003 Att1 S5"))
    audit(db, user, f"program_{kind}_recorded", f"{title} ({when})")
    db.commit()
    return redirect(f"/programs/{kind}", "Recorded and filed as evidence.", request)


@router.post("/programs/exercise/{rid}/plan-updated", dependencies=[Depends(csrf_protect)])
async def exercise_plan_updated(rid: int, request: Request, user: User = Depends(editor),
                                db: Session = Depends(get_db)):
    rec = db.get(ProgramRecord, rid)
    if not rec or rec.org_id != user.org_id or rec.kind != "exercise":
        raise HTTPException(404)
    f = await request.form()
    when = d(f, "plan_updated_on")
    if not when:
        return redirect("/programs/exercise", "Enter the date the plan was updated (or reviewed with no change).",
                        request)
    note = s(f, "note") or "Plan updated after the exercise."
    fileinfo, err = await store_upload(f.get("file"), user.org_id)
    if err:
        return redirect("/programs/exercise", err, request)
    ev = Evidence(org_id=user.org_id, requirement_id=_req(db, "CIP-003 Att1 S4.6").id,
                  title=f"Plan update after: {rec.title}", description=note, performed_on=when,
                  uploaded_by=user.email, **(fileinfo or {}))
    db.add(ev)
    db.flush()
    rec.plan_updated_on, rec.update_evidence_id = when, ev.id
    late = (when - rec.performed_on).days > 180
    audit(db, user, "plan_update_recorded", f"{rec.title}: {when}" + (" (after 180 days)" if late else ""))
    db.commit()
    return redirect("/programs/exercise", "Plan update recorded" + (" — note it was more than 180 days after the "
                                                                     "exercise." if late else "."), request)
