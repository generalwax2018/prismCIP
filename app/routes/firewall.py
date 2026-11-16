"""Upload a firewall config for an asset; get a Section 3.1 rule review filed as evidence."""
import hashlib
import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from ..auth import audit, csrf_protect, editor
from ..db import UPLOAD_DIR, get_db
from ..fwreview import looks_like_fortigate, parse_fortigate_policies, review, summarize
from ..models import Asset, Evidence, Finding, Requirement, User, utcnow
from ..web import redirect, render, templates
from .inventory import owned

router = APIRouter()
MAX_CFG = 10 * 1024 * 1024


@router.post("/assets/{aid}/firewall", dependencies=[Depends(csrf_protect)])
async def firewall_review(aid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    a = owned(db, Asset, aid, user)
    f = await request.form()
    up = f.get("file")
    if not isinstance(up, UploadFile) or not up.filename:
        return redirect(f"/assets/{aid}", "Choose a FortiGate configuration backup.", request)
    data = await up.read(MAX_CFG + 1)
    if len(data) > MAX_CFG:
        return redirect(f"/assets/{aid}", "Config is larger than 10 MB.", request)
    text = data.decode("utf-8", "replace")
    if not looks_like_fortigate(text):
        return redirect(f"/assets/{aid}", "That doesn't look like a FortiGate backup (no 'config firewall policy' "
                                          "section). Other brands aren't supported yet.", request)
    rules = parse_fortigate_policies(text)
    issues = review(rules)
    summary = summarize(rules, issues)
    at = utcnow()
    report = templates.get_template("fw_report.html").render(asset=a, org=user.org, rules=rules, issues=issues,
                                                             summary=summary, file_name=up.filename, at=at,
                                                             by=user.email, sha=hashlib.sha256(data).hexdigest())
    org_dir = UPLOAD_DIR / str(user.org_id)
    org_dir.mkdir(parents=True, exist_ok=True)
    stored = f"{uuid.uuid4().hex}.html"
    (org_dir / stored).write_bytes(report.encode())
    req = db.query(Requirement).filter_by(code="CIP-003 Att1 S3.1").first()
    db.add(Evidence(org_id=user.org_id, requirement_id=req.id, asset_id=a.id,
                    title=f"Firewall rule review — {a.name}",
                    description=f"{summary['accept']} permit rule(s) reviewed from {up.filename} "
                                f"(sha256 {hashlib.sha256(data).hexdigest()[:16]}…): {summary['high']} high, "
                                f"{summary['medium']} medium, {summary['low']} low.",
                    performed_on=at.date(), file_name=f"firewall_review_{a.name}_{at:%Y%m%d}.html"[:300],
                    stored_name=stored, sha256=hashlib.sha256(report.encode()).hexdigest(), uploaded_by=user.email))
    for i in issues:
        if i.severity == "high":
            key = f"fw:{a.id}:{i.rule}:{i.text[:40]}"
            if not db.query(Finding).filter_by(org_id=user.org_id, dedupe_key=key, status="Open").first():
                db.add(Finding(org_id=user.org_id, kind="firewall_rule", severity="high",
                               title=f"{a.name}: {i.rule} — {i.text.split('.')[0]}", detail=i.text,
                               requirement_code=i.code, dedupe_key=key))
    audit(db, user, "firewall_reviewed", f"{a.name}: {summary}")
    db.commit()
    return render(request, "fw_result.html", user, asset=a, issues=issues, summary=summary, rules=rules)
