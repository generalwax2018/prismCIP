"""Vendor offboarding checklist and periodic vendor account review (supports CIP-003-9 Section 6)."""
import hashlib
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..compliance import add_calendar_months_end
from ..db import UPLOAD_DIR, get_db
from ..models import (AccessApproval, AccessSession, AccountReview, AccountReviewItem, Evidence, OffboardStep,
                      Requirement, User, Vendor, VendorAccess, utcnow)
from ..web import d, redirect, render, s, templates
from .inventory import owned

router = APIRouter()

MANUAL_STEPS = [
    ("accounts_deleted", "Vendor VPN / remote-tool accounts deleted or disabled on the firewall or tool itself"),
    ("shared_secrets", "Shared passwords, keys or certificates the vendor knew were changed"),
    ("devices_returned", "Utility laptops, tokens, documents or data returned or confirmed destroyed"),
    ("physical_access", "Badges, keys and site access lists updated"),
]


def auto_checks(db: Session, v: Vendor) -> list[dict]:
    paths = v.access
    open_sessions = [x for p in paths for x in p.sessions if x.ended_at is None]
    pending = [w for p in paths for w in p.approvals if w.status in ("Requested", "Approved") and w.ends_at > utcnow()]
    return [
        dict(key="paths_disabled", label="Every remote access path disabled",
             ok=all(p.status == "Disabled" for p in paths),
             detail=f"{sum(p.status == 'Enabled' for p in paths)} still enabled" if paths else "no paths"),
        dict(key="no_sessions", label="No open sessions", ok=not open_sessions,
             detail=f"{len(open_sessions)} open" if open_sessions else ""),
        dict(key="windows_closed", label="No pending or future access windows", ok=not pending,
             detail=f"{len(pending)} pending/future" if pending else ""),
        dict(key="portal_revoked", label="Access-request portal link revoked", ok=not v.portal_token_hash, detail=""),
    ]


def _steps(db, v):
    have = {st.key: st for st in db.query(OffboardStep).filter_by(vendor_id=v.id).all()}
    return [dict(key=k, label=lbl, step=have.get(k)) for k, lbl in MANUAL_STEPS]


@router.get("/vendors/{vid}/offboard")
def offboard_page(vid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    v = owned(db, Vendor, vid, user)
    return render(request, "offboard.html", user, v=v, autos=auto_checks(db, v), steps=_steps(db, v))


@router.post("/vendors/{vid}/offboard", dependencies=[Depends(csrf_protect)])
async def offboard_act(vid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    v = owned(db, Vendor, vid, user)
    f = await request.form()
    a = f.get("action")
    if a == "start":
        v.status = "Offboarding"
        audit(db, user, "vendor_offboarding_started", v.name)
    elif a == "contract":
        v.contract_end = d(f, "contract_end")
        audit(db, user, "vendor_contract_end_set", f"{v.name}: {v.contract_end}")
    elif a == "disable_all":
        n = 0
        for p in v.access:
            if p.status == "Enabled":
                p.status = "Disabled"
                n += 1
            for x in p.sessions:
                if x.ended_at is None:
                    x.ended_at, x.ended_by, x.end_reason = utcnow(), user.email, "Terminated by entity"
            for w in p.approvals:
                if w.status == "Requested":
                    w.status = "Denied"
                elif w.status == "Approved" and w.ends_at > utcnow():
                    w.status, w.ends_at = "Revoked", max(w.starts_at, utcnow())
        v.portal_token_hash, v.portal_expires = None, None
        audit(db, user, "vendor_access_shut_off", f"{v.name}: {n} path(s) disabled, sessions ended, windows "
                                                  f"revoked, portal link revoked")
    elif a == "step":
        key = f.get("key")
        if key in dict(MANUAL_STEPS):
            st = db.query(OffboardStep).filter_by(vendor_id=v.id, key=key).first() or \
                OffboardStep(org_id=user.org_id, vendor_id=v.id, key=key)
            st.done_at, st.done_by, st.note = utcnow(), user.email, s(f, "note")
            db.add(st)
            audit(db, user, "vendor_offboard_step", f"{v.name}: {dict(MANUAL_STEPS)[key]}")
    elif a == "complete":
        autos, steps = auto_checks(db, v), _steps(db, v)
        if not all(x["ok"] for x in autos) or not all(x["step"] and x["step"].done_at for x in steps):
            return redirect(f"/vendors/{vid}/offboard", "Every check must pass before offboarding is complete.",
                            request)
        now = utcnow()
        rec = templates.get_template("offboard_record.html").render(v=v, org=user.org, autos=autos, steps=steps,
                                                                    by=user, at=now).encode()
        stored = f"{uuid.uuid4().hex}.html"
        (UPLOAD_DIR / str(user.org_id)).mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / str(user.org_id) / stored).write_bytes(rec)
        req = db.query(Requirement).filter_by(code="CIP-003 Att1 S6.2").first()
        db.add(Evidence(org_id=user.org_id, requirement_id=req.id, title=f"Vendor offboarded: {v.name}",
                        description=f"All {len(v.access)} remote access path(s) disabled; offboarding checklist "
                                    f"completed by {user.email}.", performed_on=now.date(),
                        file_name=f"offboarding_{v.name}.html"[:300], stored_name=stored,
                        sha256=hashlib.sha256(rec).hexdigest(), uploaded_by=user.email, locked_at=now,
                        locked_reason="Vendor offboarding record"))
        v.status, v.offboarded_on = "Offboarded", now.date()
        audit(db, user, "vendor_offboarded", v.name)
    db.commit()
    return redirect(f"/vendors/{vid}/offboard", "Saved.", request)


# ---------- account review ----------
def review_due(db: Session, org) -> tuple:
    last = (db.query(AccountReview).filter(AccountReview.org_id == org.id, AccountReview.completed_at.isnot(None))
            .order_by(AccountReview.completed_at.desc()).first())
    if not last:
        return None, None
    return last, add_calendar_months_end(last.completed_at.date(), org.account_review_months or 3)


@router.get("/access/review")
def review_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    open_ = db.query(AccountReview).filter_by(org_id=user.org_id, completed_at=None).first()
    history = (db.query(AccountReview).filter(AccountReview.org_id == user.org_id, AccountReview.completed_at.isnot(None))
               .order_by(AccountReview.completed_at.desc()).limit(10).all())
    last, due = review_due(db, user.org)
    return render(request, "account_review.html", user, review=open_, history=history, due=due)


@router.post("/access/review", dependencies=[Depends(csrf_protect)])
async def review_act(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    a = f.get("action")
    rv = db.query(AccountReview).filter_by(org_id=user.org_id, completed_at=None).first()
    if a == "start" and not rv:
        rv = AccountReview(org_id=user.org_id, started_by=user.email)
        db.add(rv)
        for p in db.query(VendorAccess).filter_by(org_id=user.org_id).all():
            for acct in p.account_list:
                seen = (db.query(AccessSession).filter(AccessSession.access_id == p.id,
                                                       AccessSession.account.ilike(acct))
                        .order_by(AccessSession.started_at.desc()).first())
                rv.items.append(AccountReviewItem(access_id=p.id, account=acct,
                                                  label=f"{p.vendor.name} → {p.asset.name} ({p.access_method})"
                                                        + (" [disabled]" if p.status == "Disabled" else ""),
                                                  last_seen=seen.started_at if seen else None))
        audit(db, user, "account_review_started", f"{len(rv.items)} account(s)")
    elif a == "decide" and rv:
        for it in rv.items:
            dec = f.get(f"decision_{it.id}")
            if dec in ("keep", "remove"):
                it.decision, it.note = dec, s(f, f"note_{it.id}")
    elif a == "complete" and rv:
        for it in rv.items:
            dec = f.get(f"decision_{it.id}")
            if dec in ("keep", "remove"):
                it.decision, it.note = dec, s(f, f"note_{it.id}")
        if any(it.decision is None for it in rv.items):
            db.commit()
            return redirect("/access/review", "Decide keep or remove for every account first.", request)
        removed = 0
        for it in rv.items:  # apply removals to the access path's account list
            if it.decision == "remove" and it.access_id:
                p = db.get(VendorAccess, it.access_id)
                if p:
                    keep = [x for x in p.account_list if x != it.account.lower()]
                    p.accounts = ", ".join(keep) or None
                    removed += 1
        now = utcnow()
        rv.completed_at, rv.completed_by = now, user.email
        rec = templates.get_template("account_review_record.html").render(rv=rv, org=user.org, at=now).encode()
        stored = f"{uuid.uuid4().hex}.html"
        (UPLOAD_DIR / str(user.org_id)).mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / str(user.org_id) / stored).write_bytes(rec)
        req = db.query(Requirement).filter_by(code="CIP-003 Att1 S6.1").first()
        ev = Evidence(org_id=user.org_id, requirement_id=req.id, title="Vendor account review",
                      description=f"{len(rv.items)} vendor account(s) reviewed; {removed} removed. Completed by "
                                  f"{user.email}.", performed_on=now.date(), file_name=f"account_review_{now:%Y%m%d}.html",
                      stored_name=stored, sha256=hashlib.sha256(rec).hexdigest(), uploaded_by=user.email,
                      locked_at=now, locked_reason="Account review record")
        db.add(ev)
        db.flush()
        rv.evidence_id = ev.id
        audit(db, user, "account_review_completed", f"{len(rv.items)} reviewed, {removed} removed")
        msg = f"Review complete: {removed} account(s) removed from PrismCIP. Delete them on the firewall/tool too."
        db.commit()
        return redirect("/access/review", msg, request)
    db.commit()
    return redirect("/access/review", "Saved.", request)


@router.post("/settings/review-cadence", dependencies=[Depends(csrf_protect)])
async def review_cadence(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    try:
        m = int(f.get("months", 3))
    except ValueError:
        m = 3
    user.org.account_review_months = max(1, min(m, 15))
    audit(db, user, "account_review_cadence_set", f"every {user.org.account_review_months} month(s)")
    db.commit()
    return redirect("/access/review", "Cadence saved.", request)
