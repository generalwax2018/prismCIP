"""PrismCIP — NERC CIP low impact compliance for small utilities."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import chain, models  # noqa: F401  (register tables; chain hooks the activity log)
from .billing import BillingRequired
from .auth import LoginRequired, PasswordChangeRequired
from .catalog import seed_requirements
from .db import Base, SessionLocal, auto_migrate, engine, server_key
from .routes import account, aidraft, auditreq, backups, board, portfolio, readiness, signup, sso, core, noncompliance, vendorlife, evidence, firewall, inventory, planedit, portal, programs, remote, reports, rsaw, signoffs
from .web import render




async def _daily_loop():
    """Daily jobs, checked every 30 minutes (server local time):
    backups after PRISMCIP_BACKUP_HOUR (default 2) unless PRISMCIP_BACKUPS=off,
    reminders after PRISMCIP_REMINDER_HOUR (default 7) unless PRISMCIP_REMINDERS=off."""
    import asyncio
    from datetime import date, datetime

    from . import backup, reminders
    jobs = []
    if os.environ.get("PRISMCIP_BACKUPS", "on") != "off":
        jobs.append(("backup", int(os.environ.get("PRISMCIP_BACKUP_HOUR", "2")),
                     lambda: backup.create(label="scheduled")))
    from . import chain as _chain
    jobs.append(("anchor", 0, _chain.anchor_all))
    if os.environ.get("PRISMCIP_REMINDERS", "on") != "off":
        def _remind():
            with SessionLocal() as db:
                reminders.run_all(db, base_url=os.environ.get("PRISMCIP_BASE_URL", ""))
        jobs.append(("reminders", int(os.environ.get("PRISMCIP_REMINDER_HOUR", "7")), _remind))
    last: dict[str, date] = {}
    while True:
        now = datetime.now()
        for name, hour, fn in jobs:
            if now.hour >= hour and last.get(name) != date.today():
                try:
                    await asyncio.to_thread(fn)
                    last[name] = date.today()
                except Exception as exc:  # never let a job failure take the app down
                    print(f"[prismcip] {name} job failed: {exc!r}")
        await asyncio.sleep(1800)


@asynccontextmanager
async def lifespan(_app):
    import asyncio
    Base.metadata.create_all(engine)
    auto_migrate()
    with SessionLocal() as db:
        seed_requirements(db)
        from .members import ensure_memberships
        ensure_memberships(db)
    chain.seal_pending()  # chains entries written before the hash chain existed, in their original order
    task = None
    if os.environ.get("PRISMCIP_REMINDERS", "on") != "off" or os.environ.get("PRISMCIP_BACKUPS", "on") != "off":
        task = asyncio.create_task(_daily_loop())
    from . import syslog
    syslog_task = asyncio.create_task(syslog.run()) if os.environ.get("PRISMCIP_SYSLOG_PORT") else None
    yield
    for tk in (task, syslog_task):
        if tk:
            tk.cancel()


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


@app.exception_handler(BillingRequired)
async def _billing_required(request: Request, _exc):
    request.session["flash"] = "Changes are paused until billing is set up. You can still read and export."
    return RedirectResponse("/billing", status_code=303)


@app.exception_handler(PasswordChangeRequired)
async def _password_change(request: Request, _exc):
    return RedirectResponse("/account/password", status_code=303)


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
for r in (account.router, aidraft.router, signup.router, sso.router, portfolio.router, readiness.router, board.router, backups.router, vendorlife.router, noncompliance.router, auditreq.router, core.router, remote.router, inventory.router, evidence.router, reports.router, signoffs.router, rsaw.router, planedit.router, programs.router, portal.router, firewall.router):
    app.include_router(r)
