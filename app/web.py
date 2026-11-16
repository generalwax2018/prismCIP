"""Shared template setup and small form helpers."""
from datetime import date, datetime
from pathlib import Path

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth import csrf_token

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["app_name"] = "PrismCIP"


def nav_counts(user) -> dict:
    if not user:
        return {}
    from .db import SessionLocal
    from .members import orgs_for
    from .models import Finding, Signoff
    with SessionLocal() as db:
        return {"open_findings": db.query(Finding).filter_by(org_id=user.org_id, status="Open").count(),
                "my_signoffs": db.query(Signoff).filter_by(org_id=user.org_id, signer_id=user.id,
                                                           status="Pending").count(),
                "orgs": [(o.id, o.name) for o, _m in orgs_for(db, user)],
                "billing": _billing(db, user)}


def _billing(db, user):
    from .billing import state
    from .models import Organization
    org = db.get(Organization, user.org_id)
    return state(org) if org else {}


def render(request: Request, name: str, user=None, **ctx):
    ctx.update(request=request, user=user, csrf=csrf_token(request), flash=request.session.pop("flash", None),
               navc=nav_counts(user))
    return templates.TemplateResponse(request, name, ctx)


def redirect(url: str, flash: str | None = None, request: Request | None = None):
    if flash and request is not None:
        request.session["flash"] = flash
    return RedirectResponse(url, status_code=303)


def s(form, key) -> str | None:
    v = form.get(key)
    v = v.strip() if isinstance(v, str) else v
    return v or None


def b(form, key) -> bool:
    return form.get(key) in ("on", "true", "1", "yes")


def d(form, key) -> date | None:
    v = s(form, key)
    return date.fromisoformat(v) if v else None


def dt(form, key) -> datetime | None:
    v = s(form, key)
    return datetime.fromisoformat(v) if v else None
