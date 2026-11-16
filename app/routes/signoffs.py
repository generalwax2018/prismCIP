"""CIP Senior Manager (or delegate) sign-offs.

The document is frozen when the sign-off is requested: its SHA-256 is stored, and checked again when the signer
decides, so nobody approves a file that changed underneath them. Approval needs the signer's password and their
typed name. An approval becomes evidence for the matching requirement, with a signature record attached.
"""
import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from ..auth import audit, csrf_protect, current_user, editor, verify_password
from ..db import UPLOAD_DIR, get_db
from ..models import Asset, Evidence, Requirement, Signoff, User, utcnow
from ..plan import build_plan
from ..web import redirect, render, s, templates
from .evidence import ALLOWED, MAX_BYTES

router = APIRouter()
STYLE = Path(__file__).resolve().parent.parent / "static" / "style.css"
KINDS = {
    "policy": ("Low impact cyber security policies (CIP-003 R1.2)", "CIP-003 R1.2"),
    "asset_review": ("CIP-002 R2 review of assets containing low impact BCS", "CIP-002 R2"),
    "plan": ("Low impact cyber security plan (CIP-003 R2)", None),
    "other": ("Other document", None),
}


def _store(org_id: int, data: bytes, ext: str) -> tuple[str, str]:
    d = UPLOAD_DIR / str(org_id) / "signoffs"
    d.mkdir(parents=True, exist_ok=True)
    name = f"{uuid.uuid4().hex}{ext}"
    (d / name).write_bytes(data)
    return name, hashlib.sha256(data).hexdigest()


def doc_path(so: Signoff) -> Path:
    return UPLOAD_DIR / str(so.org_id) / "signoffs" / so.stored_name


def snapshot(db: Session, user: User, kind: str) -> bytes:
    org = user.org
    if kind == "asset_review":
        assets = db.query(Asset).filter_by(org_id=org.id).order_by(Asset.name).all()
        html = templates.get_template("snapshot_assets.html").render(org=org, assets=assets, at=utcnow(),
                                                                      by=user.email)
    else:
        html = templates.get_template("plan_standalone.html").render(inline_css=STYLE.read_text(), for_signoff=True,
                                                                     **build_plan(db, org))
    return html.encode()


@router.get("/signoffs")
def signoffs(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Signoff).filter_by(org_id=user.org_id).order_by(Signoff.id.desc()).all()
    mine = [x for x in rows if x.status == "Pending" and x.signer_id == user.id]
    signers = db.query(User).filter_by(org_id=user.org_id, can_sign=True, active=True).order_by(User.name).all()
    return render(request, "signoffs.html", user, rows=rows, mine=mine, signers=signers, kinds=KINDS)


@router.post("/signoffs", dependencies=[Depends(csrf_protect)])
async def request_signoff(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    kind = f.get("kind")
    if kind not in KINDS:
        raise HTTPException(400)
    try:
        signer = db.get(User, int(f.get("signer_id", 0)))
    except ValueError:
        signer = None
    if not signer or signer.org_id != user.org_id or not signer.can_sign or not signer.active:
        return redirect("/signoffs", "Pick a signer. Mark the CIP Senior Manager and delegates as signers in "
                                     "Settings first.", request)
    title = s(f, "title") or KINDS[kind][0]
    upload = f.get("file")
    if kind in ("policy", "other"):
        if not isinstance(upload, UploadFile) or not upload.filename:
            return redirect("/signoffs", "Attach the document to be approved.", request)
        ext = Path(upload.filename).suffix.lower()
        if ext not in ALLOWED:
            return redirect("/signoffs", f"File type {ext or '(none)'} isn't allowed.", request)
        data = await upload.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return redirect("/signoffs", "File is larger than 50 MB.", request)
        file_name = Path(upload.filename).name[:300]
    else:
        data, ext = snapshot(db, user, kind), ".html"
        file_name = ("asset_list" if kind == "asset_review" else "low_impact_plan") + f"_{utcnow():%Y%m%d}.html"
    stored, digest = _store(user.org_id, data, ext)
    code = KINDS[kind][1]
    req = db.query(Requirement).filter_by(code=code).first() if code else None
    so = Signoff(org_id=user.org_id, kind=kind, title=title, requirement_id=req.id if req else None,
                 file_name=file_name, stored_name=stored, sha256=digest, requested_by=user.email, signer_id=signer.id)
    db.add(so)
    db.flush()
    audit(db, user, "signoff_requested", f"#{so.id} {title} → {signer.email} (sha256 {digest[:16]}…)")
    db.commit()
    return redirect(f"/signoffs/{so.id}", f"Sign-off requested from {signer.name}.", request)


@router.get("/signoffs/{sid}")
def signoff_detail(sid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    so = db.get(Signoff, sid)
    if not so or so.org_id != user.org_id:
        raise HTTPException(404)
    intact = doc_path(so).exists() and hashlib.sha256(doc_path(so).read_bytes()).hexdigest() == so.sha256
    return render(request, "signoff_detail.html", user, so=so, intact=intact, can_decide=(
        so.status == "Pending" and so.signer_id == user.id))


@router.get("/signoffs/{sid}/document")
def signoff_document(sid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    so = db.get(Signoff, sid)
    if not so or so.org_id != user.org_id or not doc_path(so).exists():
        raise HTTPException(404)
    return FileResponse(doc_path(so), filename=so.file_name, media_type="application/octet-stream")


@router.post("/signoffs/{sid}/decide", dependencies=[Depends(csrf_protect)])
async def decide(sid: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    so = db.get(Signoff, sid)
    if not so or so.org_id != user.org_id:
        raise HTTPException(404)
    if so.signer_id != user.id or so.status != "Pending" or not user.can_sign:
        raise HTTPException(403, "Only the named signer can decide this.")
    f = await request.form()
    decision = f.get("decision")
    if decision not in ("approve", "reject"):
        raise HTTPException(400)
    if not verify_password(f.get("password", ""), user.password_hash):
        return redirect(f"/signoffs/{sid}", "Password didn't match. Nothing was signed.", request)
    typed = (s(f, "signature_name") or "").strip()
    if typed.lower() != user.name.strip().lower():
        return redirect(f"/signoffs/{sid}", f"Type your name exactly as \"{user.name}\" to sign.", request)
    if not doc_path(so).exists() or hashlib.sha256(doc_path(so).read_bytes()).hexdigest() != so.sha256:
        return redirect(f"/signoffs/{sid}", "The document no longer matches its recorded hash. Request a new "
                                            "sign-off.", request)
    so.status = "Approved" if decision == "approve" else "Rejected"
    so.decided_at, so.signature_name, so.decision_note = utcnow(), typed, s(f, "note")
    if so.status == "Approved" and so.requirement_id:
        cert = templates.get_template("signoff_certificate.html").render(so=so, user=user, org=user.org).encode()
        stored, digest = _store(user.org_id, cert, ".html")
        ev_dir = UPLOAD_DIR / str(user.org_id)
        (ev_dir / stored).write_bytes(cert)  # evidence files live directly in the org folder
        ev = Evidence(org_id=user.org_id, requirement_id=so.requirement_id, title=f"Approved: {so.title}",
                      description=f"Signed by {typed} ({user.email}) on {so.decided_at:%Y-%m-%d %H:%M} UTC. "
                                  f"Document {so.file_name}, sha256 {so.sha256}. Sign-off #{so.id}.",
                      performed_on=so.decided_at.date(), file_name=f"signoff_{so.id}_record.html",
                      stored_name=stored, sha256=digest, uploaded_by=user.email)
        db.add(ev)
        db.flush()
        so.evidence_id = ev.id
    audit(db, user, f"signoff_{so.status.lower()}", f"#{so.id} {so.title}; signed as '{typed}'; sha256 {so.sha256}")
    db.commit()
    return redirect(f"/signoffs/{sid}", f"Sign-off {so.status.lower()}.", request)
