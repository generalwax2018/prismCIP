"""Vendor remote-access session import and reconciliation (CIP-003-9 Attachment 1, Section 6).

Parsers turn raw logs into session records; reconcile() maps each record to a vendor access path by account
name, checks it against approved access windows, stores it, and opens findings for anything a person must
review. Parsers never trust the input: unknown lines are skipped and counted, nothing is executed.

Supported:
  * FortiGate event logs (key=value syslog or exported .log): SSL VPN tunnel-up/down (0101039947 / 0101039948)
    and IPsec dial-up tunnel-up/down with xauthuser. Up/down events are paired by tunnelid.
  * Palo Alto GlobalProtect syslog (PAN-OS 9.1.3+ field order): gateway-connected / gateway-logout events,
    paired by user and public IP; a logout without its connect uses the login duration.
  * CSV exports from VPN or remote-support tools (GlobalProtect, BeyondTrust, Secomea, TeamViewer, ...):
    columns are detected by name (user/account, start/login, end/logout, source ip).

Live syslog delivers a tunnel's start and end in different batches, so reconcile() closes a matching open session
instead of creating a second one.
"""
from __future__ import annotations

import csv
import hashlib
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import AccessApproval, AccessSession, Finding, ImportBatch, Organization, VendorAccess, utcnow

KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
APPROVAL_GRACE = timedelta(minutes=15)
MANUAL_MATCH = timedelta(minutes=60)
LONG_SESSION = timedelta(hours=12)


@dataclass
class Record:
    account: str
    started_at: datetime  # naive UTC
    ended_at: datetime | None = None
    source_ip: str | None = None
    device: str | None = None
    key: str = ""
    end_only: bool = False  # built from a disconnect event; its start is estimated from the duration

    def finalize(self):
        if not self.key:
            basis = f"{self.device}|{self.account}|{self.started_at.isoformat()}"
            self.key = hashlib.sha256(basis.encode()).hexdigest()[:40]
        return self


@dataclass
class ParseResult:
    records: list[Record] = field(default_factory=list)
    lines: int = 0
    skipped: int = 0


# ---------------- parsing ----------------
def _to_utc(d: datetime) -> datetime:
    return d.astimezone(timezone.utc).replace(tzinfo=None) if d.tzinfo else d


def _fg_time(f: dict) -> datetime | None:
    et = f.get("eventtime")
    if et and et.isdigit():
        n = int(et)
        secs = n / 1e9 if n > 1e15 else n / 1e6 if n > 1e12 else n  # ns, us or s
        return datetime.fromtimestamp(secs, timezone.utc).replace(tzinfo=None)
    if f.get("date") and f.get("time"):
        raw = f"{f['date']} {f['time']}"
        tz = f.get("tz", "")
        try:
            if re.fullmatch(r"[+-]\d{4}", tz):
                return _to_utc(datetime.strptime(raw + tz, "%Y-%m-%d %H:%M:%S%z"))
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    return None


def parse_fortigate(text: str) -> ParseResult:
    res = ParseResult()
    open_tunnels: dict[str, Record] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        res.lines += 1
        f = {k: v.strip('"').strip() for k, v in KV.findall(line)}
        action = f.get("action", "")
        if f.get("subtype") != "vpn" or action not in ("tunnel-up", "tunnel-down"):
            res.skipped += 1
            continue
        # SSL VPN logs a web-mode and a tunnel-mode event per login; keep the tunnel one when both exist.
        if f.get("tunneltype", "").startswith("ssl-web"):
            res.skipped += 1
            continue
        user = f.get("user") or f.get("xauthuser") or ""
        if not user or user.upper() == "N/A":
            res.skipped += 1
            continue
        when = _fg_time(f)
        if not when:
            res.skipped += 1
            continue
        device = f.get("devid") or f.get("devname") or "fortigate"
        tid = f"{device}|{f.get('tunnelid') or f.get('remip')}|{user.lower()}"
        if action == "tunnel-up":
            rec = Record(account=user, started_at=when, source_ip=f.get("remip"), device=device)
            open_tunnels[tid] = rec
            res.records.append(rec)
        else:
            rec = open_tunnels.pop(tid, None)
            if rec is None:  # down without an up in this file: rebuild the start from duration
                dur = int(f["duration"]) if f.get("duration", "").isdigit() else 0
                rec = Record(account=user, started_at=when - timedelta(seconds=dur), source_ip=f.get("remip"),
                             device=device, end_only=True)
                res.records.append(rec)
            rec.ended_at = when
    for r in res.records:
        r.finalize()
    return res


def _pan_time(fields: list[str], i: int) -> datetime | None:
    """High-resolution time carries its UTC offset; plain PAN-OS times are firewall-local (treated as UTC)."""
    hi = fields[i + 33] if len(fields) > i + 33 else ""
    for v in (hi, fields[i + 3] if len(fields) > i + 3 else ""):
        v = (v or "").strip()
        if not v:
            continue
        try:
            return _to_utc(datetime.fromisoformat(v.replace("Z", "+00:00")))
        except ValueError:
            pass
        try:
            return datetime.strptime(v, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
    return None


def parse_globalprotect(text: str) -> ParseResult:
    res = ParseResult()
    open_: dict[str, Record] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        res.lines += 1
        try:
            fields = next(csv.reader([line]))
        except (csv.Error, StopIteration):
            res.skipped += 1
            continue
        try:
            i = fields.index("GLOBALPROTECT")  # type field; the CSV starts 3 fields before it
        except ValueError:
            res.skipped += 1
            continue
        g = lambda n: fields[i + n].strip() if len(fields) > i + n else ""  # noqa: E731
        event, user, status = g(5), g(9), g(25).lower()
        if event not in ("gateway-connected", "gateway-logout") or not user or (status and status != "success"):
            res.skipped += 1
            continue
        when = _pan_time(fields, i)
        if not when:
            res.skipped += 1
            continue
        device, ip = g(-1) or "panos", g(12)
        ref = f"{device}|{user.lower()}|{ip}"
        if event == "gateway-connected":
            rec = Record(account=user.split("\\")[-1], started_at=when, source_ip=ip or None, device=device)
            open_[ref] = rec
            res.records.append(rec)
        else:
            rec = open_.pop(ref, None)
            if rec is None:
                dur = int(g(27)) if g(27).isdigit() else 0
                rec = Record(account=user.split("\\")[-1], started_at=when - timedelta(seconds=dur),
                             source_ip=ip or None, device=device, end_only=True)
                res.records.append(rec)
            rec.ended_at = when
    for r in res.records:
        r.finalize()
    return res


_COLS = {
    "account": ("user", "username", "user name", "account", "login", "vendor user", "representative", "rep",
                "source user", "customer"),
    "start": ("start", "start time", "started", "login time", "logon time", "connected", "session start",
              "start_time", "begin", "time generated", "receive time"),
    "end": ("end", "end time", "ended", "logout time", "logoff time", "disconnected", "session end", "end_time"),
    "ip": ("source ip", "src ip", "source", "remote ip", "client ip", "public ip", "remip", "src", "ip"),
}
_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S",
                 "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p",
                 "%d-%b-%Y %H:%M:%S")


def _parse_dt(v: str) -> datetime | None:
    v = (v or "").strip()
    if not v:
        return None
    try:
        return _to_utc(datetime.fromisoformat(v.replace("Z", "+00:00")))
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def _pick(header: list[str], names) -> int | None:
    norm = [h.strip().lower().replace("_", " ") for h in header]
    for n in names:
        n = n.replace("_", " ")
        if n in norm:
            return norm.index(n)
    return None


def parse_csv(text: str) -> ParseResult:
    res = ParseResult()
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return res
    header = rows[0]
    idx = {k: _pick(header, v) for k, v in _COLS.items()}
    if idx["account"] is None or idx["start"] is None:
        raise ValueError("CSV needs a user/account column and a start/login time column. Found: "
                         + ", ".join(h for h in header if h)[:300])
    for row in rows[1:]:
        if not any(c.strip() for c in row):
            continue
        res.lines += 1
        get = lambda k: row[idx[k]] if idx[k] is not None and idx[k] < len(row) else ""  # noqa: E731
        acct, start = get("account").strip(), _parse_dt(get("start"))
        if not acct or not start:
            res.skipped += 1
            continue
        res.records.append(Record(account=acct, started_at=start, ended_at=_parse_dt(get("end")),
                                  source_ip=get("ip").strip() or None, device="csv").finalize())
    return res


PARSERS = {"fortigate": parse_fortigate, "globalprotect": parse_globalprotect, "csv": parse_csv}


def detect_and_parse(text: str, fmt: str = "auto") -> tuple[str, ParseResult]:
    if fmt == "auto":
        head = text[:4000]
        if "logid=" in head and "subtype=" in head:
            fmt = "fortigate"
        elif ",GLOBALPROTECT," in head:
            fmt = "globalprotect"
        else:
            fmt = "csv"
    return fmt, PARSERS.get(fmt, parse_csv)(text)


# ---------------- reconciliation ----------------
def _ignored(org: Organization) -> set[str]:
    return {a.strip().lower() for a in re.split(r"[,\n;]+", org.ignored_accounts or "") if a.strip()}


def _open_finding(db, org_id, counter, *, kind, severity, title, detail, code, access_id=None, session_id=None,
                  dedupe=None):
    if dedupe and db.query(Finding).filter_by(org_id=org_id, dedupe_key=dedupe).first():
        return
    db.add(Finding(org_id=org_id, kind=kind, severity=severity, title=title, detail=detail, requirement_code=code,
                   access_id=access_id, session_id=session_id, dedupe_key=dedupe))
    counter[0] += 1


def reconcile(db: Session, org: Organization, records: list[Record], batch: ImportBatch) -> ImportBatch:
    paths = db.query(VendorAccess).filter_by(org_id=org.id).all()
    by_account: dict[str, list[VendorAccess]] = {}
    for p in paths:
        for a in p.account_list:
            by_account.setdefault(a, []).append(p)
    ignored = _ignored(org)
    new_findings = [0]
    batch.records = len(records)

    for r in records:
        acct = r.account.strip().lower()
        if acct in ignored:
            continue
        same = db.query(AccessSession).filter_by(org_id=org.id, external_key=r.key).first()
        if same:
            if same.ended_at is None and r.ended_at:  # the end of a session whose start came in earlier
                same.ended_at, same.ended_by = r.ended_at, "log import"
                same.end_reason = same.end_reason or "Completed"
                batch.sessions_matched += 1
            else:
                batch.duplicates += 1
            continue
        matches = by_account.get(acct, [])
        if matches and r.ended_at:
            # The start of this session may have come in an earlier batch: close that open session instead.
            prior = (db.query(AccessSession)
                     .filter(AccessSession.org_id == org.id, AccessSession.access_id.in_([m.id for m in matches]),
                             AccessSession.ended_at.is_(None), AccessSession.account.ilike(r.account),
                             AccessSession.started_at >= r.started_at - timedelta(minutes=10),
                             AccessSession.started_at <= r.started_at + timedelta(minutes=10))
                     .order_by(AccessSession.started_at.desc()).first())
            if prior and r.end_only:
                prior.ended_at, prior.ended_by = r.ended_at, "log import"
                prior.end_reason = prior.end_reason or "Completed"
                batch.sessions_matched += 1
                if r.ended_at - prior.started_at > LONG_SESSION:
                    _open_finding(db, org.id, new_findings, kind="long_session", severity="low",
                                  title=f"{prior.access.vendor.name} → {prior.access.asset.name}: session longer "
                                        f"than 12 hours", detail=f"{r.account}: {prior.started_at:%Y-%m-%d %H:%M} → "
                                                                 f"{r.ended_at:%Y-%m-%d %H:%M} UTC.",
                                  code="CIP-003 Att1 S6.2", access_id=prior.access_id, session_id=prior.id,
                                  dedupe=f"long:{prior.external_key or prior.id}")
                window = db.get(AccessApproval, prior.approval_id) if prior.approval_id else None
                if window and r.ended_at > window.ends_at + APPROVAL_GRACE:
                    _open_finding(db, org.id, new_findings, kind="overrun", severity="medium",
                                  title=f"{prior.access.vendor.name} → {prior.access.asset.name}: session ran past its "
                                        f"approved window",
                                  detail=f"{r.account} stayed connected until {r.ended_at:%Y-%m-%d %H:%M} UTC; the "
                                         f"window ended {window.ends_at:%Y-%m-%d %H:%M} UTC.",
                                  code="CIP-003 Att1 S6.2", access_id=prior.access_id, session_id=prior.id,
                                  dedupe=f"overrun:{prior.external_key or prior.id}")
                continue
        if not matches:
            _open_finding(db, org.id, new_findings, kind="unmapped_account", severity="medium",
                          title=f"Remote access by unmapped account '{r.account}'",
                          detail=f"Seen {r.started_at:%Y-%m-%d %H:%M} UTC from {r.source_ip or 'unknown IP'}. "
                                 f"Map it to a vendor access path, or add it to ignored staff accounts in Settings.",
                          code="CIP-003 Att1 S6.1", dedupe=f"unmapped:{acct}")
            continue
        path = matches[0]

        # A session someone already logged by hand for this path at about this time is the same session.
        manual = next((s for s in path.sessions if s.source == "manual" and s.external_key is None
                       and abs(s.started_at - r.started_at) <= MANUAL_MATCH), None)
        if manual:
            manual.external_key, manual.source_ip, manual.account = r.key, r.source_ip, r.account
            if manual.ended_at is None and r.ended_at:
                manual.ended_at, manual.ended_by, manual.end_reason = r.ended_at, "log import", "Completed"
            sess = manual
            batch.sessions_matched += 1
        else:
            sess = AccessSession(org_id=org.id, access_id=path.id, vendor_person=r.account, account=r.account,
                                 purpose="Imported from logs", started_at=r.started_at, ended_at=r.ended_at,
                                 ended_by="log import" if r.ended_at else None,
                                 end_reason="Completed" if r.ended_at else None, source="import",
                                 external_key=r.key, source_ip=r.source_ip, import_id=batch.id)
            db.add(sess)
            db.flush()
            batch.sessions_new += 1

        label = f"{path.vendor.name} → {path.asset.name}"
        window = next((w for w in path.approvals if w.status == "Approved"
                       and w.starts_at - APPROVAL_GRACE <= r.started_at <= w.ends_at), None)
        if window:
            sess.approval_id = window.id
            if not sess.approved_by:
                sess.approved_by = window.approved_by
            if r.ended_at and r.ended_at > window.ends_at + APPROVAL_GRACE:
                _open_finding(db, org.id, new_findings, kind="overrun", severity="medium",
                              title=f"{label}: session ran past its approved window",
                              detail=f"{r.account} stayed connected until {r.ended_at:%Y-%m-%d %H:%M} UTC; the window "
                                     f"ended {window.ends_at:%Y-%m-%d %H:%M} UTC.",
                              code="CIP-003 Att1 S6.2", access_id=path.id, session_id=sess.id,
                              dedupe=f"overrun:{r.key}")
        elif not manual:
            _open_finding(db, org.id, new_findings, kind="unapproved", severity="high",
                          title=f"{label}: vendor session with no approval",
                          detail=f"{r.account} connected {r.started_at:%Y-%m-%d %H:%M} UTC from "
                                 f"{r.source_ip or 'unknown IP'} and no approved access window covers it.",
                          code="CIP-003 Att1 S6.1", access_id=path.id, session_id=sess.id,
                          dedupe=f"unapproved:{r.key}")
        if path.status == "Disabled":
            _open_finding(db, org.id, new_findings, kind="disabled_path", severity="high",
                          title=f"{label}: session on a path marked disabled",
                          detail=f"{r.account} connected {r.started_at:%Y-%m-%d %H:%M} UTC although this path is "
                                 f"disabled in PrismCIP. Check that the disable method actually works.",
                          code="CIP-003 Att1 S6.2", access_id=path.id, session_id=sess.id,
                          dedupe=f"disabled:{r.key}")
        if r.ended_at and r.ended_at - r.started_at > LONG_SESSION:
            _open_finding(db, org.id, new_findings, kind="long_session", severity="low",
                          title=f"{label}: session longer than 12 hours",
                          detail=f"{r.account}: {r.started_at:%Y-%m-%d %H:%M} → {r.ended_at:%Y-%m-%d %H:%M} UTC.",
                          code="CIP-003 Att1 S6.2", access_id=path.id, session_id=sess.id, dedupe=f"long:{r.key}")
        if len(matches) > 1:
            _open_finding(db, org.id, new_findings, kind="shared_account", severity="low",
                          title=f"Account '{r.account}' is mapped to {len(matches)} access paths",
                          detail="Sessions are attributed to the first path. Shared vendor accounts make it hard "
                                 "to show who accessed what; consider one account per path.",
                          code="CIP-003 Att1 S6.1", dedupe=f"shared:{acct}")
    batch.findings_new = new_findings[0]
    return batch


def import_text(db: Session, org: Organization, text: str, *, by: str, fmt: str = "auto",
                file_name: str | None = None, source: str | None = None) -> tuple[ImportBatch, ParseResult]:
    fmt, parsed = detect_and_parse(text, fmt)
    batch = ImportBatch(org_id=org.id, by=by, source=source or fmt, file_name=file_name,
                        sha256=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest())
    db.add(batch)
    db.flush()
    reconcile(db, org, parsed.records, batch)
    return batch, parsed


def utc_now() -> datetime:
    return utcnow()
