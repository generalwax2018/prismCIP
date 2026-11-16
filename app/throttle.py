"""Sign-in throttling. Failed attempts are counted per account and per client IP over a sliding window.

Per account: 5 failures in 15 minutes locks that account for the rest of the window (stops guessing one user).
Per IP: 20 failures in 15 minutes blocks that IP (stops spraying many users). The message never says which.
"""
from datetime import timedelta

from fastapi import Request
from sqlalchemy.orm import Session

from .models import LoginAttempt, utcnow

WINDOW = timedelta(minutes=15)
PER_ACCOUNT = 5
PER_IP = 20
RETENTION = timedelta(days=30)
MESSAGE = "Too many attempts. Wait 15 minutes and try again."


def client_ip(request: Request) -> str:
    return (request.client.host if request.client else "unknown")[:64]


def blocked(db: Session, email: str, ip: str, kind: str = "password") -> bool:
    since = utcnow() - WINDOW
    q = db.query(LoginAttempt).filter(LoginAttempt.at >= since, LoginAttempt.ok.is_(False),
                                      LoginAttempt.kind == kind)
    if email and q.filter(LoginAttempt.email == email).count() >= PER_ACCOUNT:
        return True
    return q.filter(LoginAttempt.ip == ip).count() >= PER_IP


def record(db: Session, email: str, ip: str, ok: bool, kind: str = "password") -> None:
    db.add(LoginAttempt(email=(email or "")[:200], ip=ip, ok=ok, kind=kind))
    if ok:  # a success clears that account's recent failures
        db.query(LoginAttempt).filter(LoginAttempt.email == email, LoginAttempt.ok.is_(False),
                                      LoginAttempt.kind == kind,
                                      LoginAttempt.at >= utcnow() - WINDOW).delete(synchronize_session=False)
    db.query(LoginAttempt).filter(LoginAttempt.at < utcnow() - RETENTION).delete(synchronize_session=False)
    db.commit()
