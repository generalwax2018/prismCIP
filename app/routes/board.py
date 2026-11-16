"""One-page status report for the general manager to hand to the co-op board."""
from datetime import date, timedelta
from pathlib import Path

from .. import readiness
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import audit, current_user
from ..compliance import requirement_statuses
from ..db import get_db
from ..models import (AccessSession, AuditLog, AuditRequest, Finding, Noncompliance, Signoff, User, Vendor,
                      VendorAccess, utcnow)
from ..web import render, templates

router = APIRouter()
STYLE = Path(__file__).resolve().parent.parent / "static" / "style.css"


def board_data(db: Session, user: User) -> dict:
    org, today = user.org, date.today()
    statuses = requirement_statuses(db, org, today)
    good = [s for s in statuses if s.css == "ok"]
    bad = [s for s in statuses if s.css == "bad"]
    warn = [s for s in statuses if s.css == "warn"]
    attention = sorted(bad + warn, key=lambda s: (s.css != "bad", s.due or date.max))[:6]
    upcoming = sorted([s for s in statuses if s.due and today <= s.due <= today + timedelta(days=90)],
                      key=lambda s: s.due)
    since = utcnow() - timedelta(days=90)
    sessions = db.query(AccessSession).filter(AccessSession.org_id == org.id, AccessSession.started_at >= since).all()
    approved = [x for x in sessions if x.source == "manual" or x.approval_id]
    year_start = date(today.year, 1, 1)
    nc = db.query(Noncompliance).filter(Noncompliance.org_id == org.id).all()
    nc_year = [x for x in nc if x.discovered_on >= year_start]
    last_export = (db.query(AuditLog).filter_by(org_id=org.id, action="audit_package_exported")
                   .order_by(AuditLog.id.desc()).first())

    def last_signed(kind):
        so = (db.query(Signoff).filter_by(org_id=org.id, kind=kind, status="Approved")
              .order_by(Signoff.decided_at.desc()).first())
        return so.decided_at.date() if so else None

    total = len(statuses)
    if not bad and not warn:
        headline = "All tracked NERC CIP low impact obligations are in good shape."
    elif bad:
        headline = (f"{len(bad)} of {total} obligations are overdue or missing evidence and need action; "
                    f"{len(good)} are in good shape.")
    else:
        headline = f"{len(good)} of {total} obligations are in good shape; {len(warn)} need attention soon."
    return dict(
        org=org, today=today, headline=headline, total=total, good=len(good), bad=len(bad), warn=len(warn),
        pct=round(100 * len(good) / total) if total else 0, attention=attention, upcoming=upcoming,
        sessions=len(sessions), approved=len(approved),
        unapproved=db.query(Finding).filter(Finding.org_id == org.id, Finding.kind == "unapproved",
                                            Finding.created_at >= since).count(),
        paths_enabled=db.query(VendorAccess).filter_by(org_id=org.id, status="Enabled").count(),
        vendors_offboarded=db.query(Vendor).filter(Vendor.org_id == org.id, Vendor.offboarded_on.isnot(None),
                                                   Vendor.offboarded_on >= year_start).count(),
        high_findings=db.query(Finding).filter_by(org_id=org.id, status="Open", severity="high").count(),
        nc_open=sum(1 for x in nc if x.status != "Closed"), nc_year=len(nc_year),
        nc_closed_year=sum(1 for x in nc_year if x.status == "Closed"),
        nc_reported_year=sum(1 for x in nc_year if x.disposition in ("Self-report submitted", "Self-logged")),
        rfis_open=db.query(AuditRequest).filter(AuditRequest.org_id == org.id,
                                                AuditRequest.status.in_(("Open", "In progress"))).count(),
        last_export=last_export.at.date() if last_export else None,
        policy_signed=last_signed("policy"), assets_signed=last_signed("asset_review"),
        plan_signed=last_signed("plan"), prepared_by=user.name, ready=readiness.summary(db, org.id))


@router.get("/reports/board")
def board(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "board.html", user, **board_data(db, user))


@router.get("/reports/board/download")
def board_download(user: User = Depends(current_user), db: Session = Depends(get_db)):
    data = board_data(db, user)
    html = templates.get_template("board_standalone.html").render(inline_css=STYLE.read_text(), **data)
    audit(db, user, "board_report_downloaded")
    db.commit()
    return Response(html, media_type="text/html", headers={
        "Content-Disposition": f'attachment; filename="PrismCIP_board_report_{data["today"]}.html"'})
