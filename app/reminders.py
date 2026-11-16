"""Due-date and follow-up reminders. Each reminder is sent once per milestone (60, 30, 7 days before, and when
overdue), so running this every hour or every day is safe."""
from dataclasses import dataclass
from datetime import date

from sqlalchemy.orm import Session

from . import mailer
from .compliance import requirement_statuses
from .models import Finding, Organization, ReminderLog, Signoff, User, utcnow

MILESTONES = (60, 30, 7)


@dataclass
class Item:
    key: str
    text: str
    severity: str  # bad | warn
    to_signer: int | None = None  # user id when only one person should get it


def collect(db: Session, org: Organization, today: date | None = None) -> list[Item]:
    today = today or date.today()
    items: list[Item] = []
    for st in requirement_statuses(db, org, today):
        r = st.req
        if not r.cadence_months:
            continue
        if st.due is None:
            items.append(Item(f"req:{r.code}:never:{today:%Y-%m}", f"{r.code} — {r.title}: never performed. "
                              f"Required at least once every {r.cadence_months} calendar months.", "bad"))
            continue
        days = (st.due - today).days
        if days < 0:
            items.append(Item(f"req:{r.code}:{st.due}:overdue", f"{r.code} — {r.title}: OVERDUE since {st.due} "
                              f"(last done {st.last_performed}).", "bad"))
            continue
        hit = next((m for m in sorted(MILESTONES) if days <= m), None)
        if hit:
            items.append(Item(f"req:{r.code}:{st.due}:{hit}", f"{r.code} — {r.title}: due by {st.due} "
                              f"({days} day{'s' if days != 1 else ''} left).", "warn"))
    week = today.isocalendar()
    for so in db.query(Signoff).filter_by(org_id=org.id, status="Pending").all():
        if (utcnow() - so.requested_at).days >= 2:
            items.append(Item(f"signoff:{so.id}:{week[0]}-{week[1]}", f"Sign-off waiting for you: {so.title} "
                              f"(requested by {so.requested_by} on {so.requested_at:%Y-%m-%d}).", "warn",
                              to_signer=so.signer_id))
    for x in db.query(Finding).filter_by(org_id=org.id, status="Open", severity="high").all():
        items.append(Item(f"finding:{x.id}", f"High finding: {x.title}", "bad"))
    return items


def pending(db: Session, org: Organization, today: date | None = None) -> list[Item]:
    sent = {r.key for r in db.query(ReminderLog.key).filter_by(org_id=org.id).all()}
    return [i for i in collect(db, org, today) if i.key not in sent]


def _recipients(db: Session, org: Organization) -> list[User]:
    return [u for u in db.query(User).filter_by(org_id=org.id, active=True, notify=True).all()
            if u.role in ("admin", "editor") or u.can_sign]


def send_due(db: Session, org: Organization, today: date | None = None, base_url: str = "") -> dict:
    items = pending(db, org, today)
    if not items:
        return {"sent": 0, "messages": 0}
    people = _recipients(db, org)
    messages = 0
    general = [i for i in items if i.to_signer is None]
    if general:
        to = [u.email for u in people if u.role in ("admin", "editor")]
        if to:
            mailer.send(to, f"PrismCIP: {len(general)} compliance item(s) need attention — {org.name}",
                        _body(org, general, base_url))
            messages += 1
        for i in general:
            db.add(ReminderLog(org_id=org.id, key=i.key, recipients=", ".join(to)))
    for i in [i for i in items if i.to_signer]:
        signer = db.get(User, i.to_signer)
        if signer and signer.active and signer.notify:
            mailer.send([signer.email], "PrismCIP: a sign-off is waiting for you", _body(org, [i], base_url))
            messages += 1
        db.add(ReminderLog(org_id=org.id, key=i.key, recipients=signer.email if signer else ""))
    db.commit()
    return {"sent": len(items), "messages": messages}


def _body(org: Organization, items: list[Item], base_url: str) -> str:
    lines = [f"{org.name} — NERC CIP low impact compliance", ""]
    for i in items:
        lines.append(("! " if i.severity == "bad" else "- ") + i.text)
    lines += ["", f"Open PrismCIP: {base_url or 'your PrismCIP site'}",
              "You get this because reminders are on for your account (Settings → your account)."]
    return "\n".join(lines)


def run_all(db: Session, today: date | None = None, base_url: str = "") -> dict:
    total = {"orgs": 0, "sent": 0, "messages": 0}
    for org in db.query(Organization).all():
        r = send_due(db, org, today, base_url)
        total["orgs"] += 1
        total["sent"] += r["sent"]
        total["messages"] += r["messages"]
    return total
