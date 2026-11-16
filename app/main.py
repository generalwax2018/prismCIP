"""PrismCIP — NERC CIP low impact compliance for small utilities."""
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import models  # noqa: F401  (register tables)
from .auth import LoginRequired
from .catalog import seed_requirements
from .db import DATA_DIR, Base, SessionLocal, engine
from .routes import core, evidence, inventory, reports
from .web import render


def _secret_key() -> str:
    key = os.environ.get("PRISMCIP_SECRET_KEY")
    if key:
        return key
    f = DATA_DIR / ".secret_key"
    if not f.exists():
        f.write_text(secrets.token_urlsafe(48))
        f.chmod(0o600)
    return f.read_text().strip()


@asynccontextmanager
async def lifespan(_app):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_requirements(db)
    yield


app = FastAPI(title="PrismCIP", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=_secret_key(), session_cookie="prismcip",
                   same_site="lax", https_only=os.environ.get("PRISMCIP_HTTPS", "0") == "1",
                   max_age=60 * 60 * 12)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                            "frame-ancestors 'none'; form-action 'self'")
    return resp


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, _exc):
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    msg = exc.detail if exc.status_code != 404 else "Not found."
    resp = render(request, "error.html", None, code=exc.status_code, message=msg)
    resp.status_code = exc.status_code
    return resp


@app.get("/healthz")
def healthz():
    return {"ok": True}


app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
for r in (core.router, inventory.router, evidence.router, reports.router):
    app.include_router(r)
