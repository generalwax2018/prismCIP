"""Co-op / consultant mode: one login across several utilities, a portfolio view, and switching between them."""
import os
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import csrf_protect, current_user
from ..compliance import requirement_statuses, summary_counts
from ..db import get_db
from ..members import membership, orgs_for, switch
from ..models import AuditLog, AuditRequest, Finding, Membership, Noncompliance, Organization, User
from ..web import redirect, render, s

router = APIRouter()


def can_create_orgs(user: User) -> bool:
    listed = {e.strip().lower() for e in (os.environ.get("PRISMCIP_PLATFORM_ADMINS", "") + "," +
                                          os.environ.get("PRISMCIP_PARTNERS", "")).split(",") if e.strip()}
    return bool(user.is_partner) or user.email.lower() in listed


@router.get("/portfolio")
def portfolio(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = []
    for org, m in orgs_for(db, user):
        st = requirement_statuses(db, org)
        c = summary_counts(st)
        upcoming = sorted([x for x in st if x.due and x.due >= date.today()], key=lambda x: x.due)
        rows.append(dict(org=org, role=m.role, counts=c, total=len(st),
                         pct=round(100 * c["ok"] / len(st)) if st else 0,
                         overdue=sum(1 for x in st if x.status in ("Overdue", "No evidence")),
                         high=db.query(Finding).filter_by(org_id=org.id, status="Open", severity="high").count(),
                         rfis=db.query(AuditRequest).filter(AuditRequest.org_id == org.id,
                                                            AuditRequest.status.in_(("Open", "In progress"))).count(),
                         nc=db.query(Noncompliance).filter(Noncompliance.org_id == org.id,
                                                           Noncompliance.status != "Closed").count(),
                         next_due=upcoming[0] if upcoming else None))
    rows.sort(key=lambda r: (-r["overdue"], -r["high"], r["org"].name))
    return render(request, "portfolio.html", user, rows=rows, can_create=can_create_orgs(user))


@router.post("/orgs/switch", dependencies=[Depends(csrf_protect)])
async def switch_org(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = await request.form()
    try:
        target = int(f.get("org_id", 0))
    except ValueError:
        raise HTTPException(400)
    old = user.org_id
    if request.session.get("org_lock") and target != request.session["org_lock"]:
        raise HTTPException(403, "You signed in with this utility's single sign-on. Sign in again to open another.")
    if target == old:
        return redirect(f.get("next") or "/")
    if not switch(db, user, target):
        raise HTTPException(403, "You don't have access to that utility.")
    db.add(AuditLog(org_id=target, actor=user.email, action="switched_in", detail=f"from organization #{old}"))
    db.commit()
    org = db.get(Organization, target)
    return redirect("/", f"Now working in {org.name}.", request)


@router.post("/orgs", dependencies=[Depends(csrf_protect)])
async def create_org(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not can_create_orgs(user):
        raise HTTPException(403, "Only partner accounts can add utilities.")
    f = await request.form()
    if not s(f, "name"):
        return redirect("/portfolio", "Name the utility.", request)
    org = Organization(name=s(f, "name"), ncr_id=s(f, "ncr_id"), regional_entity=s(f, "regional_entity"),
                       registered_functions=s(f, "registered_functions"))
    db.add(org)
    db.flush()
    db.add(Membership(user_id=user.id, org_id=org.id, role="admin"))
    db.add(AuditLog(org_id=org.id, actor=user.email, action="organization_created", detail=org.name))
    db.flush()
    switch(db, user, org.id)
    db.commit()
    return redirect("/", f"Created {org.name}. Add its assets, then invite its staff in Settings.", request)
