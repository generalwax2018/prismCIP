"""Outbound email. Uses SMTP when PRISMCIP_SMTP_HOST is set; otherwise writes .eml files to <data>/outbox so
reminders can be checked without a mail server."""
import os
import smtplib
import ssl
import uuid
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from .db import DATA_DIR

OUTBOX = DATA_DIR / "outbox"


def smtp_configured() -> bool:
    return bool(os.environ.get("PRISMCIP_SMTP_HOST"))


def describe() -> str:
    if smtp_configured():
        return f"SMTP via {os.environ['PRISMCIP_SMTP_HOST']}:{os.environ.get('PRISMCIP_SMTP_PORT', '587')}"
    return f"No SMTP server set; messages are saved to {OUTBOX}"


def send(to: list[str], subject: str, text: str, html: str | None = None) -> str:
    if not to:
        return "no recipients"
    sender = os.environ.get("PRISMCIP_MAIL_FROM", "prismcip@localhost")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, ", ".join(to), subject
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain="prismcip")
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    if not smtp_configured():
        OUTBOX.mkdir(parents=True, exist_ok=True)
        path = OUTBOX / f"{uuid.uuid4().hex}.eml"
        path.write_bytes(bytes(msg))
        return f"saved {path.name}"
    host, port = os.environ["PRISMCIP_SMTP_HOST"], int(os.environ.get("PRISMCIP_SMTP_PORT", "587"))
    user, pw = os.environ.get("PRISMCIP_SMTP_USER"), os.environ.get("PRISMCIP_SMTP_PASSWORD")
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as s:
            if user:
                s.login(user, pw or "")
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as s:
            s.starttls(context=ctx)
            if user:
                s.login(user, pw or "")
            s.send_message(msg)
    return "sent"
