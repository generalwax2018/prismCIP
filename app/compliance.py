"""Due-date engine and gap detection.

"At least once every N calendar months" is computed as: due by the last day of the calendar month that is
N months after the month the activity was last performed. Example: done 2026-03-10, 15 months -> due by
2027-06-30. Confirm this reading with your Regional Entity's guidance.
"""
import calendar
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy.orm import Session

from .models import AccessSession, Asset, Evidence, Finding, Organization, Requirement, VendorAccess, utcnow

DUE_SOON_DAYS = 60
RETENTION_YEARS = 3


def add_calendar_months_end(d: date, months: int) -> date:
    total = d.month - 1 + months
    year, month = d.year + total // 12, total % 12 + 1
    return date(year, month, calendar.monthrange(year, month)[1])


@dataclass
class ReqStatus:
    req: Requirement
    status: str  # Current | Due soon | Overdue | No evidence | Documented | Gap
    last_performed: date | None = None
    due: date | None = None
    evidence_count: int = 0
    gaps: list[str] = field(default_factory=list)

    @property
    def css(self):
        return {"Current": "ok", "Documented": "ok", "Due soon": "warn", "Overdue": "bad",
                "No evidence": "bad", "Gap": "warn"}[self.status]


def detect_gaps(db: Session, org: Organization) -> dict[str, list[str]]:
    gaps: dict[str, list[str]] = {}

    def add(code, msg):
        gaps.setdefault(code, []).append(msg)

    assets = db.query(Asset).filter_by(org_id=org.id).all()
    if not assets:
        add("CIP-002 R1.3", "No assets recorded yet.")
    if not org.cip_senior_manager:
        add("CIP-003 R3", "No CIP Senior Manager named in Settings.")

    for a in assets:
        if not a.physical_access_control:
            add("CIP-003 Att1 S2", f"{a.name}: physical access controls not described.")
        if a.routable_external and not a.electronic_access_control:
            add("CIP-003 Att1 S3.1", f"{a.name}: has routable external connectivity but no electronic "
                                     f"access control described.")
        if a.dialup:
            add("CIP-003 Att1 S3.2", f"{a.name}: has dial-up — make sure authentication evidence is on file.")
        paths = [p for p in a.vendor_access]
        if a.vendor_remote_access_allowed and not paths:
            add("CIP-003 Att1 S6.1", f"{a.name}: allows vendor remote access but no access paths recorded.")
        if not a.vendor_remote_access_allowed and any(p.status == "Enabled" for p in paths):
            add("CIP-003 Att1 S6.1", f"{a.name}: marked as not allowing vendor remote access, but has an "
                                     f"enabled vendor access path.")

    paths = db.query(VendorAccess).filter_by(org_id=org.id).all()
    for p in paths:
        label = f"{p.vendor.name} → {p.asset.name} ({p.access_method})"
        if not p.determine_method:
            add("CIP-003 Att1 S6.1", f"{label}: no method to determine access.")
        if not p.disable_method:
            add("CIP-003 Att1 S6.2", f"{label}: no method to disable access.")
        if not p.detect_method:
            add("CIP-003 Att1 S6.3", f"{label}: no method to detect malicious communications.")

    stale = utcnow() - timedelta(hours=24)
    open_sessions = (db.query(AccessSession)
                     .filter(AccessSession.org_id == org.id, AccessSession.ended_at.is_(None),
                             AccessSession.started_at < stale).all())
    for s in open_sessions:
        add("CIP-003 Att1 S6.2", f"Session by {s.vendor_person} on {s.access.asset.name} has been open "
                                 f"more than 24 hours.")
    for x in (db.query(Finding).filter(Finding.org_id == org.id, Finding.status == "Open",
                                       Finding.severity.in_(("high", "medium"))).all()):
        if x.requirement_code:
            add(x.requirement_code, f"Open finding: {x.title}")
    return gaps


def requirement_statuses(db: Session, org: Organization, today: date | None = None) -> list[ReqStatus]:
    today = today or date.today()
    gaps = detect_gaps(db, org)
    out = []
    reqs = db.query(Requirement).order_by(Requirement.sort_order).all()
    last_test = None
    test_req = next((r for r in reqs if r.code == "CIP-003 Att1 S4.5"), None)
    if test_req:
        t = (db.query(Evidence).filter_by(org_id=org.id, requirement_id=test_req.id)
             .order_by(Evidence.performed_on.desc()).first())
        last_test = t.performed_on if t else None
    for req in reqs:
        ev = (db.query(Evidence).filter_by(org_id=org.id, requirement_id=req.id)
              .order_by(Evidence.performed_on.desc()).all())
        last = ev[0].performed_on if ev else None
        st = ReqStatus(req=req, status="No evidence", last_performed=last, evidence_count=len(ev),
                       gaps=gaps.get(req.code, []))
        if req.code == "CIP-003 Att1 S4.6":
            # Event-driven: after a test, the plan update (if any is needed) is due within 180 calendar days.
            if last_test and not (last and last >= last_test):
                st.due = last_test + timedelta(days=180)
                st.status = "Overdue" if today > st.due else "Due soon" if (st.due - today).days <= DUE_SOON_DAYS \
                    else "Current"
                st.gaps.append(f"Plan update (or a note that none was needed) after the {last_test} test is due by "
                               f"{st.due}.")
            elif last:
                st.status = "Documented"
            else:
                st.status = "Documented" if not last_test else st.status
            out.append(st)
            continue
        if req.cadence_months and last:
            st.due = add_calendar_months_end(last, req.cadence_months)
            if today > st.due:
                st.status = "Overdue"
            elif (st.due - today).days <= DUE_SOON_DAYS:
                st.status = "Due soon"
            else:
                st.status = "Current"
        elif last:
            st.status = "Documented"
        if st.gaps and st.status in ("Current", "Documented"):
            st.status = "Gap"
        out.append(st)
    return out


def summary_counts(statuses: list[ReqStatus]) -> dict[str, int]:
    counts = {"ok": 0, "warn": 0, "bad": 0}
    for s in statuses:
        counts[s.css] += 1
    return counts


def retention_cutoff(today: date | None = None) -> date:
    today = today or date.today()
    try:
        return today.replace(year=today.year - RETENTION_YEARS)
    except ValueError:  # Feb 29
        return today.replace(year=today.year - RETENTION_YEARS, day=28)
