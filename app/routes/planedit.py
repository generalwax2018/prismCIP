"""Plan narrative editor."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..auth import audit, csrf_protect, editor
from ..db import get_db
from ..models import Narrative, User, utcnow
from ..plan import SECTIONS
from ..web import redirect, render

router = APIRouter()


@router.get("/plan/edit")
def plan_edit(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    have = {n.key[5:]: n for n in db.query(Narrative).filter(Narrative.org_id == user.org_id,
                                                             Narrative.key.like("plan:%")).all()}
    return render(request, "plan_edit.html", user, sections=SECTIONS, have=have)


@router.post("/plan/edit", dependencies=[Depends(csrf_protect)])
async def plan_save(request: Request, user: User = Depends(editor), db: Session = Depends(get_db)):
    f = await request.form()
    changed = []
    for key, title, _ in SECTIONS:
        body = (f.get(key) or "").strip()
        n = db.query(Narrative).filter_by(org_id=user.org_id, key=f"plan:{key}").first()
        if n is None and body:
            db.add(Narrative(org_id=user.org_id, key=f"plan:{key}", body=body, updated_by=user.email))
            changed.append(title)
        elif n is not None and n.body != body:
            n.body, n.updated_by, n.updated_at = body, user.email, utcnow()
            changed.append(title)
    if changed:
        audit(db, user, "plan_sections_saved", "; ".join(changed))
        db.commit()
    return redirect("/plan", f"Saved {len(changed)} plan section(s)." if changed else "No changes.", request)
