"""Possible noncompliance log. Records facts and the entity's own decisions; PrismCIP doesn't decide what to report."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..db import get_db
from ..models import Finding, MitigationStep, Noncompliance, Requirement, User, utcnow
from ..web import d, redirect, render, s
from .inventory import owned

router = APIRouter()
HOW = ["Internal review", "PrismCIP finding", "Session import", "Firewall review", "Self-certification",
       "Spot check", "Compliance audit", "Other"]
CAUSES = ["People", "Process", "Technology", "Vendor", "Other"]
RISKS = ["Minimal", "Moderate", "Serious"]
DISPOSITIONS = ["Not yet decided", "Self-report submitted", "Self-logged", "Determined not a noncompliance",
                "Identified by the Regional Entity"]
STATUSES = ["Open", "Mitigating", "Closed"]


def _fill(x: Noncompliance, f):
    x.title = s(f, "title") or x.title
    x.description = s(f, "description") or x.description
    x.discovered_on = d(f, "discovered_on") or x.discovered_on
    x.discovered_how = f.get("discovered_how") if f.get("discovered_how") in HOW else x.discovered_how
    x.started_on, x.ended_on = d(f, "started_on"), d(f, "ended_on")
    x.cause_category = f.get("cause_category") if f.get("cause_category") in CAUSES else None
    x.root_cause, x.risk_rationale = s(f, "root_cause"), s(f, "risk_rationale")
    x.risk = f.get("risk") if f.get("risk") in RISKS else None
    x.disposition = f.get("disposition") if f.get("disposition") in DISPOSITIONS else x.disposition
    x.submitted_on, x.tracking_id = d(f, "submitted_on"), s(f, "tracking_id")


@router.get("/noncompliance")
def nc_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Noncompliance).filter_by(org_id=user.org_id).order_by(Noncompliance.id.desc()).all()
    reqs = db.query(Requirement).order_by(Requirement.sort_order).all()
    finding = None
    if request.query_params.get("finding"):
        try:
            finding = owned(db, Finding, int(request.query_params["finding"]), user)
        except (ValueError, HTTPException):
            finding = None
    from datetime import date
    return render(request, "noncompliance.html", user, rows=rows, reqs=reqs, how=HOW, finding=finding,
                  today=date.today())


@router.post("/noncompliance", dependencies=[Depends(csrf_protect)])
async def nc_create(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    try:
        req = db.get(Requirement, int(f.get("requirement_id", 0)))
    except ValueError:
        req = None
    if not req or not s(f, "title") or not s(f, "description") or not d(f, "discovered_on"):
        return redirect("/noncompliance", "Needs the requirement, a title, what happened and when it was found.",
                        request)
    x = Noncompliance(org_id=user.org_id, requirement_id=req.id, title=s(f, "title"), description=s(f, "description"),
                      discovered_on=d(f, "discovered_on"),
                      discovered_how=f.get("discovered_how") if f.get("discovered_how") in HOW else "Other",
                      created_by=user.email)
    if s(f, "finding_id"):
        try:
            fi = owned(db, Finding, int(f["finding_id"]), user)
            x.finding_id = fi.id
        except (ValueError, HTTPException):
            pass
    db.add(x)
    db.flush()
    audit(db, user, "noncompliance_recorded", f"#{x.id} {req.code}: {x.title}")
    db.commit()
    return redirect(f"/noncompliance/{x.id}", "Recorded. Add the cause, risk and mitigation steps.", request)


@router.get("/noncompliance/{nid}")
def nc_detail(nid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    x = owned(db, Noncompliance, nid, user)
    finding = db.get(Finding, x.finding_id) if x.finding_id else None
    from datetime import date
    return render(request, "noncompliance_detail.html", user, x=x, finding=finding, how=HOW, causes=CAUSES,
                  risks=RISKS, dispositions=DISPOSITIONS, today=date.today())


@router.post("/noncompliance/{nid}", dependencies=[Depends(csrf_protect)])
async def nc_update(nid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    x = owned(db, Noncompliance, nid, user)
    if x.status == "Closed":
        return redirect(f"/noncompliance/{nid}", "Closed records can't be edited. Reopen it first.", request)
    f = await request.form()
    before = (x.risk, x.disposition)
    _fill(x, f)
    if x.status == "Open" and x.steps:
        x.status = "Mitigating"
    audit(db, user, "noncompliance_updated", f"#{x.id}" + (f"; risk {before[0]}→{x.risk}" if before[0] != x.risk else "")
          + (f"; disposition {before[1]}→{x.disposition}" if before[1] != x.disposition else ""))
    db.commit()
    return redirect(f"/noncompliance/{nid}", "Saved.", request)


@router.post("/noncompliance/{nid}/steps", dependencies=[Depends(csrf_protect)])
async def nc_step(nid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    x = owned(db, Noncompliance, nid, user)
    f = await request.form()
    if f.get("complete"):
        st = db.get(MitigationStep, int(f["complete"]))
        if st and st.noncompliance_id == x.id and not st.completed_on:
            st.completed_on = d(f, "completed_on") or utcnow().date()
            audit(db, user, "mitigation_step_completed", f"#{x.id}: {st.text}")
            db.commit()
        return redirect(f"/noncompliance/{nid}", "Step marked complete.", request)
    if not s(f, "text"):
        return redirect(f"/noncompliance/{nid}", "Describe the step.", request)
    db.add(MitigationStep(noncompliance_id=x.id, text=s(f, "text"), owner=s(f, "owner"), due_on=d(f, "due_on")))
    if x.status == "Open":
        x.status = "Mitigating"
    audit(db, user, "mitigation_step_added", f"#{x.id}: {s(f, 'text')}")
    db.commit()
    return redirect(f"/noncompliance/{nid}", "Mitigation step added.", request)


@router.post("/noncompliance/{nid}/status", dependencies=[Depends(csrf_protect)])
async def nc_status(nid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    x = owned(db, Noncompliance, nid, user)
    f = await request.form()
    if f.get("action") == "close":
        missing = [m for m, ok in (("the end date of the noncompliance", x.ended_on), ("the root cause", x.root_cause),
                                   ("the risk", x.risk)) if not ok]
        open_steps = [st for st in x.steps if not st.completed_on]
        if missing or open_steps or x.disposition == "Not yet decided":
            parts = missing + ([f"{len(open_steps)} open mitigation step(s)"] if open_steps else []) + \
                (["a decision on reporting"] if x.disposition == "Not yet decided" else [])
            return redirect(f"/noncompliance/{nid}", "Before closing, record " + ", ".join(parts) + ".", request)
        x.status, x.closed_on = "Closed", utcnow().date()
        audit(db, user, "noncompliance_closed", f"#{x.id}")
    elif f.get("action") == "reopen" and x.status == "Closed":
        x.status, x.closed_on = "Mitigating" if x.steps else "Open", None
        audit(db, user, "noncompliance_reopened", f"#{x.id}")
    db.commit()
    return redirect(f"/noncompliance/{nid}", f"Status: {x.status}.", request)
