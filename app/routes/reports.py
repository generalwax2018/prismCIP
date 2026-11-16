"""Generated plan and the audit package export."""
import csv
import io
import zipfile
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import audit, current_user
from ..compliance import requirement_statuses, retention_cutoff
from ..db import get_db
from ..models import AccessSession, Asset, AuditLog, Evidence, User, VendorAccess
from ..plan import build_plan
from ..web import render, templates
from .evidence import evidence_path

router = APIRouter()
STYLE = Path(__file__).resolve().parent.parent / "static" / "style.css"


@router.get("/plan")
def plan(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "plan.html", user, **build_plan(db, user.org))


def _csv(rows, header) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_. " else "_" for c in name).strip() or "file"


def evidence_zip_path(e) -> str:
    """Where an evidence file sits inside the audit package. The RSAW workbook links to the same paths."""
    if not e.stored_name:
        return ""
    return f"evidence/{_safe(e.requirement.code)}/{e.id}_{_safe(e.file_name or 'file')}"


@router.get("/export")
def export(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    org = user.org
    today = date.today()
    cutoff = retention_cutoff(today)
    statuses = requirement_statuses(db, org, today)
    assets = db.query(Asset).filter_by(org_id=org.id).order_by(Asset.name).all()
    paths = db.query(VendorAccess).filter_by(org_id=org.id).all()
    sessions = (db.query(AccessSession).filter_by(org_id=org.id).order_by(AccessSession.started_at).all())
    evidence = (db.query(Evidence).filter_by(org_id=org.id).order_by(Evidence.performed_on).all())
    logs = db.query(AuditLog).filter_by(org_id=org.id).order_by(AuditLog.id).all()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        summary = templates.get_template("export_summary.html").render(
            org=org, today=today, cutoff=cutoff, statuses=statuses, n_assets=len(assets), n_paths=len(paths),
            n_sessions=len(sessions), n_evidence=len(evidence))
        z.writestr("00_summary.html", summary)
        plan_html = templates.get_template("plan_standalone.html").render(inline_css=STYLE.read_text(), **build_plan(db, org))
        z.writestr("01_cip003_low_impact_plan_DRAFT.html", plan_html)
        z.writestr("02_assets.csv", _csv(
            [[a.name, a.asset_type, a.location or "", a.impact_rating, a.routable_external, a.dialup,
              a.vendor_remote_access_allowed, a.physical_access_control or "", a.electronic_access_control or ""]
             for a in assets],
            ["asset", "type", "location", "impact", "routable_external", "dialup",
             "vendor_remote_access_allowed", "physical_access_control", "electronic_access_control"]))
        z.writestr("03_vendor_remote_access.csv", _csv(
            [[p.vendor.name, p.asset.name, p.access_method, p.status, p.determine_method or "",
              p.disable_method or "", p.detect_method or "", p.approved_by or "", p.approved_on or ""]
             for p in paths],
            ["vendor", "asset", "method", "status", "6.1_determine", "6.2_disable", "6.3_detect",
             "approved_by", "approved_on"]))
        z.writestr("04_vendor_sessions.csv", _csv(
            [[x.access.vendor.name, x.access.asset.name, x.vendor_person, x.purpose, x.approved_by or "",
              x.started_at, x.ended_at or "", x.ended_by or "", x.end_reason or "", x.malicious_activity_noted,
              x.notes or ""] for x in sessions],
            ["vendor", "asset", "vendor_person", "purpose", "approved_by", "started_utc", "ended_utc",
             "ended_by", "end_reason", "malicious_activity_noted", "notes"]))
        idx = []
        for e in evidence:
            path_in_zip = ""
            if e.stored_name and evidence_path(e).exists():
                path_in_zip = evidence_zip_path(e)
                z.write(evidence_path(e), path_in_zip)
            idx.append([e.requirement.code, e.title, e.performed_on, e.asset.name if e.asset else "",
                        e.uploaded_by, e.uploaded_at, e.sha256 or "", path_in_zip,
                        "yes" if e.performed_on >= cutoff else "older than retention window"])
        z.writestr("05_evidence_index.csv", _csv(
            idx, ["requirement", "title", "performed_on", "asset", "uploaded_by", "uploaded_utc", "sha256",
                  "file_in_package", "within_3yr_retention"]))
        from .rsaw import render_export
        z.writestr("07_rsaw_workbook.html", render_export(db, org))
        from ..models import Finding, Signoff
        from .signoffs import doc_path
        so_rows = []
        for so in db.query(Signoff).filter_by(org_id=org.id).order_by(Signoff.id).all():
            p = ""
            if so.stored_name and doc_path(so).exists():
                p = f"signoffs/{so.id}_{_safe(so.file_name or 'document')}"
                z.write(doc_path(so), p)
            so_rows.append([so.id, so.title, so.requirement.code if so.requirement else so.kind, so.status,
                            so.requested_by, so.requested_at, so.signer.name, so.signature_name or "",
                            so.decided_at or "", so.sha256, p])
        z.writestr("08_signoffs.csv", _csv(so_rows, ["id", "document", "requirement", "status", "requested_by",
                                                     "requested_utc", "signer", "signed_as", "decided_utc",
                                                     "document_sha256", "file_in_package"]))
        z.writestr("09_findings.csv", _csv(
            [[x.id, x.severity, x.status, x.requirement_code or "", x.title, x.detail or "", x.created_at,
              x.resolved_by or "", x.resolution or ""]
             for x in db.query(Finding).filter_by(org_id=org.id).order_by(Finding.id).all()],
            ["id", "severity", "status", "requirement", "title", "detail", "found_utc", "resolved_by", "resolution"]))
        z.writestr("06_activity_log.csv", _csv(
            [[r.at, r.actor, r.action, r.detail or ""] for r in logs], ["at_utc", "actor", "action", "detail"]))

    audit(db, user, "audit_package_exported", f"{len(evidence)} evidence items")
    db.commit()
    fname = f"PrismCIP_audit_package_{_safe(org.name).replace(' ', '_')}_{today.isoformat()}.zip"
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})
