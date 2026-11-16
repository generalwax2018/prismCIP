"""Vendor access-request portal.

Each vendor gets a private link. Only a SHA-256 of the token is stored; links expire and issuing a new one revokes
the old one. Through it a vendor can see which of its access paths exist (asset name and method only) and request
an access window. Requests land as "Requested" approvals for the utility to approve or deny.
"""
import hashlib
import hmac
import secrets
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import mailer
from ..auth import audit, csrf_protect, editor
from ..db import get_db
from ..models import AccessApproval, AuditLog, User, Vendor, VendorAccess
from ..web import dt, redirect, render, s
from .inventory import owned

router = APIRouter()
LINK_DAYS = 180
MAX_PENDING = 10


def _hash(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def _vendor_for(db: Session, token: str) -> Vendor | None:
    if not token or len(token) > 100:
        return None
    v = db.query(Vendor).filter_by(portal_token_hash=_hash(token)).first()
    if not v or not hmac.compare_digest(v.portal_token_hash, _hash(token)):
        return None
    if v.portal_expires and v.portal_expires < date.today():
        return None
    return v


@router.post("/vendors/{vid}/portal", dependencies=[Depends(csrf_protect)])
async def portal_link(vid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    v = owned(db, Vendor, vid, user)
    f = await request.form()
    if f.get("action") == "revoke":
        v.portal_token_hash, v.portal_expires = None, None
        audit(db, user, "vendor_portal_revoked", v.name)
        db.commit()
        return redirect(f"/vendors/{vid}", "Portal link revoked.", request)
    tok = secrets.token_urlsafe(24)
    v.portal_token_hash, v.portal_expires = _hash(tok), date.today() + timedelta(days=LINK_DAYS)
    audit(db, user, "vendor_portal_issued", f"{v.name}, expires {v.portal_expires}")
    db.commit()
    link = f"{str(request.base_url).rstrip('/')}/portal/{tok}"
    return redirect(f"/vendors/{vid}", f"Portal link for {v.name} (shown once, send it to the vendor): {link}",
                    request)


@router.get("/portal/{token}")
def portal(token: str, request: Request, db: Session = Depends(get_db)):
    v = _vendor_for(db, token)
    if not v:
        raise HTTPException(404, "This link isn't valid. Ask the utility for a new one.")
    paths = [p for p in v.access if p.status == "Enabled"]
    recent = (db.query(AccessApproval).filter(AccessApproval.access_id.in_([p.id for p in v.access] or [0]))
              .order_by(AccessApproval.id.desc()).limit(10).all())
    return render(request, "portal.html", None, vendor=v, paths=paths, recent=recent, token=token)


@router.post("/portal/{token}", dependencies=[Depends(csrf_protect)])
async def portal_request(token: str, request: Request, db: Session = Depends(get_db)):
    v = _vendor_for(db, token)
    if not v:
        raise HTTPException(404, "This link isn't valid. Ask the utility for a new one.")
    f = await request.form()
    try:
        path = db.get(VendorAccess, int(f.get("access_id", 0)))
    except ValueError:
        path = None
    start, end = dt(f, "starts_at"), dt(f, "ends_at")
    person, purpose = s(f, "person"), s(f, "purpose")
    back = f"/portal/{token}"
    if not path or path.vendor_id != v.id or path.status != "Enabled":
        return redirect(back, "Pick one of the listed sites.", request)
    if not (start and end and end > start and person and purpose) or f.get("terms") != "on":
        return redirect(back, "Fill in every field, make the end later than the start, and accept the terms.", request)
    if end - start > timedelta(days=7):
        return redirect(back, "Request at most 7 days at a time.", request)
    pending = db.query(AccessApproval).filter(AccessApproval.access_id.in_([p.id for p in v.access]),
                                              AccessApproval.status == "Requested").count()
    if pending >= MAX_PENDING:
        return redirect(back, "Too many requests are already waiting. Contact the utility.", request)
    w = AccessApproval(org_id=v.org_id, access_id=path.id, starts_at=start, ends_at=end, purpose=purpose[:2000],
                       ticket=(s(f, "ticket") or "")[:100] or None, requested_by=person[:200], status="Requested",
                       approved_by=None)
    db.add(w)
    db.add(AuditLog(org_id=v.org_id, actor=f"vendor portal: {v.name}", action="access_window_requested",
                    detail=f"{person} for {path.asset.name}, {start:%Y-%m-%d %H:%M}–{end:%Y-%m-%d %H:%M} UTC: {purpose}"))
    db.commit()
    from ..members import members
    to = [u.email for u, m in members(db, v.org_id, active_only=True, notify_only=True)
          if m.role in ("admin", "editor")]
    try:
        mailer.send(to, f"PrismCIP: {v.name} requests remote access to {path.asset.name}",
                    f"{person} ({v.name}) asks for access to {path.asset.name} via {path.access_method}\n"
                    f"From {start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC\nPurpose: {purpose}\n\n"
                    f"Approve or deny it on the access path page in PrismCIP.")
    except Exception as exc:  # the request is saved either way
        print(f"[prismcip] portal notification failed: {exc!r}")
    return redirect(back, "Request sent. You'll be able to connect once the utility approves it.", request)
