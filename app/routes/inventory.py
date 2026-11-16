"""Assets, vendors, vendor remote access paths and sessions (CIP-002 R1 + CIP-003 Att1 S2/S3/S6)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, current_user, editor
from ..db import get_db
from ..models import AccessSession, Asset, User, Vendor, VendorAccess, utcnow
from ..web import b, d, dt, redirect, render, s

router = APIRouter()
ASSET_TYPES = ["Substation", "Generation", "Control Center", "Backup Control Center", "Other"]
ACCESS_METHODS = ["Client VPN", "Jump host / bastion", "Vendor remote support tool", "Cellular modem",
                  "Dial-up modem", "Site-to-site VPN", "Other"]
END_REASONS = ["Completed", "Terminated by entity", "Suspicious activity", "Timed out"]


def owned(db: Session, model, oid: int, user: User):
    obj = db.get(model, oid)
    if not obj or obj.org_id != user.org_id:
        raise HTTPException(404)
    return obj


# ---------- assets ----------
def _asset_from_form(a: Asset, f):
    a.name = s(f, "name")
    a.asset_type = s(f, "asset_type") or "Other"
    a.location = s(f, "location")
    a.routable_external = b(f, "routable_external")
    a.dialup = b(f, "dialup")
    a.vendor_remote_access_allowed = b(f, "vendor_remote_access_allowed")
    a.electronic_access_control = s(f, "electronic_access_control")
    a.physical_access_control = s(f, "physical_access_control")
    a.notes = s(f, "notes")


@router.get("/assets")
def assets(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Asset).filter_by(org_id=user.org_id).order_by(Asset.name).all()
    return render(request, "assets.html", user, rows=rows)


@router.get("/assets/new")
def asset_new(request: Request, user: User = Depends(editor)):
    return render(request, "asset_form.html", user, a=None, types=ASSET_TYPES)


@router.post("/assets/new", dependencies=[Depends(csrf_protect)])
async def asset_create(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    if not s(f, "name"):
        return render(request, "asset_form.html", user, a=None, types=ASSET_TYPES, error="Name is required.")
    a = Asset(org_id=user.org_id)
    _asset_from_form(a, f)
    db.add(a)
    db.flush()
    audit(db, user, "asset_added", a.name)
    db.commit()
    return redirect(f"/assets/{a.id}", "Asset added.", request)


@router.get("/assets/{aid}")
def asset_detail(aid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = owned(db, Asset, aid, user)
    vendors = db.query(Vendor).filter_by(org_id=user.org_id).order_by(Vendor.name).all()
    return render(request, "asset_detail.html", user, a=a, types=ASSET_TYPES, vendors=vendors,
                  methods=ACCESS_METHODS)


@router.post("/assets/{aid}", dependencies=[Depends(csrf_protect)])
async def asset_update(aid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    a = owned(db, Asset, aid, user)
    f = await request.form()
    if not s(f, "name"):
        return redirect(f"/assets/{aid}", "Name is required.", request)
    _asset_from_form(a, f)
    audit(db, user, "asset_updated", a.name)
    db.commit()
    return redirect(f"/assets/{aid}", "Saved.", request)


@router.post("/assets/{aid}/delete", dependencies=[Depends(csrf_protect)])
def asset_delete(aid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    a = owned(db, Asset, aid, user)
    audit(db, user, "asset_deleted", a.name)
    db.delete(a)
    db.commit()
    return redirect("/assets", "Asset deleted.", request)


# ---------- vendors ----------
@router.get("/vendors")
def vendors(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Vendor).filter_by(org_id=user.org_id).order_by(Vendor.name).all()
    return render(request, "vendors.html", user, rows=rows)


@router.post("/vendors", dependencies=[Depends(csrf_protect)])
async def vendor_create(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    if not s(f, "name"):
        return redirect("/vendors", "Vendor name is required.", request)
    v = Vendor(org_id=user.org_id, name=s(f, "name"), contact=s(f, "contact"), services=s(f, "services"))
    db.add(v)
    db.flush()
    audit(db, user, "vendor_added", v.name)
    db.commit()
    return redirect(f"/vendors/{v.id}", "Vendor added.", request)


@router.get("/vendors/{vid}")
def vendor_detail(vid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    v = owned(db, Vendor, vid, user)
    assets = db.query(Asset).filter_by(org_id=user.org_id).order_by(Asset.name).all()
    return render(request, "vendor_detail.html", user, v=v, assets=assets, methods=ACCESS_METHODS)


@router.post("/vendors/{vid}", dependencies=[Depends(csrf_protect)])
async def vendor_update(vid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    v = owned(db, Vendor, vid, user)
    f = await request.form()
    v.name = s(f, "name") or v.name
    v.contact, v.services = s(f, "contact"), s(f, "services")
    audit(db, user, "vendor_updated", v.name)
    db.commit()
    return redirect(f"/vendors/{vid}", "Saved.", request)


@router.post("/vendors/{vid}/delete", dependencies=[Depends(csrf_protect)])
def vendor_delete(vid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    v = owned(db, Vendor, vid, user)
    audit(db, user, "vendor_deleted", v.name)
    db.delete(v)
    db.commit()
    return redirect("/vendors", "Vendor deleted.", request)


# ---------- vendor remote access paths ----------
@router.post("/access", dependencies=[Depends(csrf_protect)])
async def access_create(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    try:
        v = owned(db, Vendor, int(f.get("vendor_id", 0)), user)
        a = owned(db, Asset, int(f.get("asset_id", 0)), user)
    except (ValueError, HTTPException):
        return redirect(request.headers.get("referer", "/vendors"), "Pick a vendor and an asset.", request)
    p = VendorAccess(org_id=user.org_id, vendor_id=v.id, asset_id=a.id,
                     access_method=s(f, "access_method") or "Other")
    db.add(p)
    if not a.vendor_remote_access_allowed:
        a.vendor_remote_access_allowed = True
    db.flush()
    audit(db, user, "vendor_access_added", f"{v.name} → {a.name} via {p.access_method}")
    db.commit()
    return redirect(f"/access/{p.id}", "Access path added. Now document the Section 6 methods.", request)


@router.get("/access")
def access_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(VendorAccess).filter_by(org_id=user.org_id).all()
    rows.sort(key=lambda p: (p.vendor.name, p.asset.name))
    return render(request, "access_list.html", user, rows=rows)


@router.get("/access/{pid}")
def access_detail(pid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = owned(db, VendorAccess, pid, user)
    return render(request, "access_detail.html", user, p=p, methods=ACCESS_METHODS, end_reasons=END_REASONS,
                  now=utcnow().strftime("%Y-%m-%dT%H:%M"))


@router.post("/access/{pid}", dependencies=[Depends(csrf_protect)])
async def access_update(pid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    p = owned(db, VendorAccess, pid, user)
    f = await request.form()
    p.access_method = s(f, "access_method") or p.access_method
    p.determine_method, p.disable_method, p.detect_method = (s(f, "determine_method"), s(f, "disable_method"),
                                                             s(f, "detect_method"))
    p.approved_by, p.approved_on = s(f, "approved_by"), d(f, "approved_on")
    p.accounts = s(f, "accounts")
    audit(db, user, "vendor_access_updated", f"{p.vendor.name} → {p.asset.name}")
    db.commit()
    return redirect(f"/access/{pid}", "Saved.", request)


@router.post("/access/{pid}/toggle", dependencies=[Depends(csrf_protect)])
def access_toggle(pid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    p = owned(db, VendorAccess, pid, user)
    p.status = "Disabled" if p.status == "Enabled" else "Enabled"
    closed = 0
    if p.status == "Disabled":
        for sess in p.sessions:
            if sess.ended_at is None:
                sess.ended_at, sess.ended_by, sess.end_reason = utcnow(), user.email, "Terminated by entity"
                closed += 1
    audit(db, user, "vendor_access_" + p.status.lower(),
          f"{p.vendor.name} → {p.asset.name}" + (f"; closed {closed} open session(s)" if closed else ""))
    db.commit()
    return redirect(f"/access/{pid}", f"Access {p.status.lower()}.", request)


@router.post("/access/{pid}/delete", dependencies=[Depends(csrf_protect)])
def access_delete(pid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    p = owned(db, VendorAccess, pid, user)
    audit(db, user, "vendor_access_deleted", f"{p.vendor.name} → {p.asset.name}")
    vid = p.vendor_id
    db.delete(p)
    db.commit()
    return redirect(f"/vendors/{vid}", "Access path deleted.", request)


# ---------- sessions ----------
@router.post("/access/{pid}/sessions", dependencies=[Depends(csrf_protect)])
async def session_start(pid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    p = owned(db, VendorAccess, pid, user)
    if p.status != "Enabled":
        return redirect(f"/access/{pid}", "This access path is disabled. Enable it before logging a session.",
                        request)
    f = await request.form()
    if not s(f, "vendor_person") or not s(f, "purpose"):
        return redirect(f"/access/{pid}", "Session needs the vendor person and purpose.", request)
    sess = AccessSession(org_id=user.org_id, access_id=p.id, vendor_person=s(f, "vendor_person"),
                         purpose=s(f, "purpose"), approved_by=s(f, "approved_by") or user.email,
                         started_at=dt(f, "started_at") or utcnow(), notes=s(f, "notes"))
    db.add(sess)
    audit(db, user, "session_started", f"{sess.vendor_person} on {p.asset.name}: {sess.purpose}")
    db.commit()
    return redirect(f"/access/{pid}", "Session logged.", request)


@router.post("/sessions/{sid}/end", dependencies=[Depends(csrf_protect)])
async def session_end(sid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    sess = owned(db, AccessSession, sid, user)
    f = await request.form()
    if sess.ended_at is None:
        sess.ended_at = dt(f, "ended_at") or utcnow()
        sess.ended_by = user.email
        sess.end_reason = s(f, "end_reason") or "Completed"
        sess.malicious_activity_noted = b(f, "malicious_activity_noted")
        if s(f, "notes"):
            sess.notes = ((sess.notes + "\n") if sess.notes else "") + s(f, "notes")
        audit(db, user, "session_ended", f"{sess.vendor_person}: {sess.end_reason}"
              + ("; MALICIOUS ACTIVITY NOTED" if sess.malicious_activity_noted else ""))
        db.commit()
    return redirect(f"/access/{sess.access_id}", "Session closed.", request)
