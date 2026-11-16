"""PrismCIP — NERC CIP low impact compliance for small utilities."""
import os
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
from .db import Base, SessionLocal, auto_migrate, engine, server_key
from .routes import core, evidence, firewall, inventory, planedit, portal, programs, remote, reports, rsaw, signoffs
from .web import render




async def _reminder_loop():
    """Once a day after PRISMCIP_REMINDER_HOUR (server local time, default 7), send due reminders."""
    import asyncio
    from datetime import date, datetime

    from . import reminders
    hour = int(os.environ.get("PRISMCIP_REMINDER_HOUR", "7"))
    last = None
    while True:
        now = datetime.now()
        if now.hour >= hour and last != date.today():
            try:
                with SessionLocal() as db:
                    reminders.run_all(db, base_url=os.environ.get("PRISMCIP_BASE_URL", ""))
                last = date.today()
            except Exception as exc:  # never let a mail problem take the app down
                print(f"[prismcip] reminder run failed: {exc!r}")
        await asyncio.sleep(1800)


@asynccontextmanager
async def lifespan(_app):
    import asyncio
    Base.metadata.create_all(engine)
    auto_migrate()
    with SessionLocal() as db:
        seed_requirements(db)
    task = None
    if os.environ.get("PRISMCIP_REMINDERS", "on") != "off":
        task = asyncio.create_task(_reminder_loop())
    yield
    if task:
        task.cancel()


app = FastAPI(title="PrismCIP", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=server_key(), session_cookie="prismcip",
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
for r in (core.router, remote.router, inventory.router, evidence.router, reports.router, signoffs.router, rsaw.router, planedit.router, programs.router, portal.router, firewall.router):
    app.include_router(r)
