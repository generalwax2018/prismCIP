"""AI suggestion routes: ask, accept (with edits), discard; and the per-utility switch."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import ai
from ..auth import admin, audit, csrf_protect, editor
from ..db import get_db
from ..models import AiSuggestion, Narrative, Requirement, User, utcnow
from ..plan import SECTIONS
from ..web import redirect

router = APIRouter()
PLAN_KEYS = {k for k, _t, _h in SECTIONS}


def _back(key: str) -> str:
    if key.startswith("rsaw:"):
        return "/rsaw"
    return "/plan/edit#" + key[5:]


@router.post("/ai/rsaw/{rid}", dependencies=[Depends(csrf_protect)])
async def ask_rsaw(rid: int, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    req = db.get(Requirement, rid)
    if not req:
        raise HTTPException(404)
    if not ai.enabled(user.org):
        raise HTTPException(403, "AI drafting is off for this utility.")
    try:
        ai.suggest(db, user.org, user, f"rsaw:{req.code}", ai.rsaw_prompt(db, user.org, req.code))
    except ai.AIError as e:
        return redirect(f"/rsaw#r{rid}", str(e), request)
    audit(db, user, "ai_suggestion_requested", f"RSAW {req.code} ({ai.model()})")
    db.commit()
    return redirect(f"/rsaw#r{rid}", f"AI suggestion ready for {req.code}. Read it before accepting.", request)


@router.post("/ai/plan/{key}", dependencies=[Depends(csrf_protect)])
async def ask_plan(key: str, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    if key not in PLAN_KEYS:
        raise HTTPException(404)
    if not ai.enabled(user.org):
        raise HTTPException(403, "AI drafting is off for this utility.")
    f = await request.form()
    current = (f.get(key) or "").strip()
    if not current:
        n = db.query(Narrative).filter_by(org_id=user.org_id, key=f"plan:{key}").first()
        current = n.body if n else ""
    try:
        ai.suggest(db, user.org, user, f"plan:{key}", ai.plan_prompt(db, user.org, key, current))
    except ai.AIError as e:
        return redirect(_back(f"plan:{key}"), str(e), request)
    audit(db, user, "ai_suggestion_requested", f"plan section {key} ({ai.model()})")
    db.commit()
    return redirect(_back(f"plan:{key}"), "AI suggestion ready. Unsaved edits in other sections weren't kept.",
                    request)


@router.post("/ai/suggestions/{sid}/{action}", dependencies=[Depends(csrf_protect)])
async def decide(sid: int, action: str, request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    sug = db.get(AiSuggestion, sid)
    if not sug or sug.org_id != user.org_id:
        raise HTTPException(404)
    if sug.status != "Pending" or action not in ("accept", "discard"):
        return redirect(_back(sug.key), "That suggestion was already handled.", request)
    f = await request.form()
    sug.decided_by, sug.decided_at = user.email, utcnow()
    if action == "discard":
        sug.status = "Discarded"
        audit(db, user, "ai_suggestion_discarded", f"#{sug.id} {sug.key}")
        db.commit()
        return redirect(_back(sug.key), "Suggestion discarded.", request)
    text = (f.get(f"suggestion_{sid}") or sug.body).strip()
    edited = text != sug.body.strip()
    n = db.query(Narrative).filter_by(org_id=user.org_id, key=sug.key).first()
    if n is None:
        n = Narrative(org_id=user.org_id, key=sug.key, body=text, updated_by=user.email)
        db.add(n)
    n.body, n.updated_by, n.updated_at = text, user.email, utcnow()
    sug.status = "Accepted"
    audit(db, user, "ai_suggestion_accepted", f"#{sug.id} {sug.key} ({sug.model}){' with edits' if edited else ''}")
    db.commit()
    left = "[CONFIRM:" in text
    return redirect(_back(sug.key), "Accepted into your text." + (" It still has [CONFIRM: …] notes to fill in."
                                                                    if left else ""), request)


@router.post("/settings/ai", dependencies=[Depends(csrf_protect)])
async def toggle(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    if not ai.server_configured():
        raise HTTPException(404)
    f = await request.form()
    user.org.ai_enabled = f.get("ai_enabled") == "on"
    audit(db, user, "ai_drafting_" + ("enabled" if user.org.ai_enabled else "disabled"))
    db.commit()
    return redirect("/settings", "AI drafting " + ("on." if user.org.ai_enabled else "off."), request)
