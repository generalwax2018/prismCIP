"""RSAW-aligned workbook: for each requirement, what an auditor looks for, the entity's written response, and
an evidence table in the shape RSAWs ask for (file, title, revision, date, relevant section, applicability).

Wording here is PrismCIP's own summary, not NERC's RSAW text. Use the current RSAW from your Regional Entity as the
form of record; this workbook is the material you copy into it and the evidence index that goes with it.
"""
from collections import defaultdict
from datetime import date

from sqlalchemy.orm import Session

from .compliance import requirement_statuses
from .models import (AccessApproval, AccessSession, Asset, Delegation, Evidence, Finding, Narrative, Organization,
                     Signoff, VendorAccess)

# Group requirements the way RSAWs are laid out.
SECTIONS = [
    ("CIP-002-5.1a", "R1 — Identify assets containing low impact BCS", ["CIP-002 R1.3"]),
    ("CIP-002-5.1a", "R2 — Review and approve every 15 calendar months", ["CIP-002 R2"]),
    ("CIP-003-9", "R1 — Policies for low impact (Part 1.2)", ["CIP-003 R1.2"]),
    ("CIP-003-9", "R2 — Implement the low impact plan (Attachment 1)",
     ["CIP-003 Att1 S1", "CIP-003 Att1 S2", "CIP-003 Att1 S3.1", "CIP-003 Att1 S3.2", "CIP-003 Att1 S4",
      "CIP-003 Att1 S4.5", "CIP-003 Att1 S4.6", "CIP-003 Att1 S5", "CIP-003 Att1 S6.1", "CIP-003 Att1 S6.2",
      "CIP-003 Att1 S6.3"]),
    ("CIP-003-9", "R3 — CIP Senior Manager", ["CIP-003 R3"]),
    ("CIP-003-9", "R4 — Delegations", ["CIP-003 R4"]),
]

AUDITOR_FOCUS = {
    "CIP-002 R1.3": "The process used to identify assets, and a list showing each asset that contains low impact "
                    "BCS. A list of the individual low impact systems is not expected.",
    "CIP-002 R2": "Dated reviews of the identifications no more than 15 calendar months apart, each approved by the "
                  "CIP Senior Manager or a delegate, plus updates made when something changed.",
    "CIP-003 R1.2": "The policy document(s) covering every low impact topic, including vendor electronic remote "
                    "access, and CIP Senior Manager approvals no more than 15 calendar months apart.",
    "CIP-003 Att1 S1": "Proof that cyber security practices were reinforced at least once every 15 calendar months: "
                       "the material and when and how it was delivered.",
    "CIP-003 Att1 S2": "How physical access to each asset (or the BCS locations in it) and to Section 3.1 access "
                       "control devices is limited based on need.",
    "CIP-003 Att1 S3.1": "For each asset with routable communication crossing its boundary: the controls in place, "
                         "the rules that permit traffic, and the reason each is needed.",
    "CIP-003 Att1 S3.2": "Authentication on any dial-up connectivity, or a statement that none exists.",
    "CIP-003 Att1 S4": "The incident response plan(s) and that they cover identification, classification, "
                       "response, E-ISAC notification, roles, and incident handling.",
    "CIP-003 Att1 S4.5": "A test of each plan at least once every 36 calendar months: tabletop, drill, or a real "
                         "reportable incident.",
    "CIP-003 Att1 S4.6": "Plan updates, if needed, within 180 calendar days after a test or a reportable incident.",
    "CIP-003 Att1 S5": "The methods used to mitigate malicious code risk from transient devices and removable media, "
                       "and records showing they were followed.",
    "CIP-003 Att1 S6.1": "For assets that allow vendor electronic remote access: the method used to know when that "
                         "access occurs, and records showing it working during the audit period.",
    "CIP-003 Att1 S6.2": "The method used to disable vendor electronic remote access, and evidence that it can be "
                         "and has been used.",
    "CIP-003 Att1 S6.3": "The method used to detect known or suspected malicious communications, inbound and "
                         "outbound, on vendor remote access paths, and records of its operation.",
    "CIP-003 R3": "A document naming the CIP Senior Manager, and changes recorded within 30 calendar days.",
    "CIP-003 R4": "Documented delegations by name or title with dates, and changes recorded within 30 calendar days.",
}


def _in_period(d: date, org: Organization) -> bool:
    if org.audit_period_start and d < org.audit_period_start:
        return False
    if org.audit_period_end and d > org.audit_period_end:
        return False
    return True


def draft(db: Session, org: Organization, code: str) -> str:
    """A first draft of the entity response, built only from what PrismCIP has recorded."""
    assets = db.query(Asset).filter_by(org_id=org.id).order_by(Asset.name).all()
    paths = db.query(VendorAccess).filter_by(org_id=org.id).all()
    sessions = [s for s in db.query(AccessSession).filter_by(org_id=org.id).all() if _in_period(s.started_at.date(), org)]
    names = ", ".join(a.name for a in assets) or "no assets recorded"
    va_assets = [a for a in assets if a.vendor_remote_access_allowed]
    if code == "CIP-002 R1.3":
        return (f"{org.name} has identified {len(assets)} asset(s) containing low impact BES Cyber Systems: {names}. "
                f"The list is maintained in PrismCIP; see the attached asset list.")
    if code == "CIP-002 R2":
        signed = db.query(Signoff).filter_by(org_id=org.id, kind="asset_review", status="Approved").all()
        dates = ", ".join(f"{x.decided_at:%Y-%m-%d} ({x.signature_name})" for x in signed) or "none recorded"
        return (f"The identifications are reviewed and approved at least once every 15 calendar months. "
                f"Approvals recorded: {dates}.")
    if code == "CIP-003 R1.2":
        signed = db.query(Signoff).filter_by(org_id=org.id, kind="policy", status="Approved").all()
        dates = ", ".join(f"{x.decided_at:%Y-%m-%d} ({x.signature_name})" for x in signed) or "none recorded"
        return ("The low impact cyber security policy addresses cyber security awareness, physical security, "
                "electronic access controls, incident response, transient cyber assets and removable media, vendor "
                f"electronic remote access security controls, and CIP Exceptional Circumstances. CIP Senior Manager "
                f"approvals: {dates}.")
    if code == "CIP-003 Att1 S2":
        lines = [f"{a.name}: {a.physical_access_control or 'not yet described'}" for a in assets]
        return "Physical access is controlled based on need at each asset.\n" + "\n".join(lines)
    if code == "CIP-003 Att1 S3.1":
        routable = [a for a in assets if a.routable_external]
        if not routable:
            return "No asset has routable communication crossing its boundary to or from low impact BCS."
        lines = [f"{a.name}: {a.electronic_access_control or 'not yet described'}" for a in routable]
        return ("Where routable communication crosses the asset boundary, only necessary inbound and outbound "
                "access is permitted.\n" + "\n".join(lines))
    if code == "CIP-003 Att1 S3.2":
        dial = [a.name for a in assets if a.dialup]
        return ("Dial-up connectivity exists at: " + ", ".join(dial) + ". It is authenticated as described in the "
                "attached evidence.") if dial else "No dial-up connectivity to low impact BCS exists."
    if code.startswith("CIP-003 Att1 S6"):
        if not va_assets:
            return "No asset containing low impact BCS allows vendor electronic remote access."
        field = {"CIP-003 Att1 S6.1": "determine_method", "CIP-003 Att1 S6.2": "disable_method",
                 "CIP-003 Att1 S6.3": "detect_method"}[code]
        verb = {"CIP-003 Att1 S6.1": "determine", "CIP-003 Att1 S6.2": "disable",
                "CIP-003 Att1 S6.3": "detect malicious communications on"}[code]
        lines = [f"{p.vendor.name} → {p.asset.name} ({p.access_method}): {getattr(p, field) or 'not yet described'}"
                 for p in paths]
        imported = sum(1 for s in sessions if s.external_key)
        approved = sum(1 for s in sessions if s.approval_id or s.source == "manual")
        windows = db.query(AccessApproval).filter_by(org_id=org.id, status="Approved").count()
        extra = ""
        if code == "CIP-003 Att1 S6.1":
            extra = (f"\nDuring the audit period {len(sessions)} vendor session(s) are recorded, {imported} confirmed "
                     f"from VPN/remote-access logs and {approved} tied to an approval ({windows} approved access "
                     f"window(s) on file).")
        if code == "CIP-003 Att1 S6.2":
            ended = sum(1 for s in sessions if s.end_reason == "Terminated by entity")
            extra = f"\nThe entity terminated {ended} vendor session(s) during the audit period."
        return (f"Vendor electronic remote access is allowed at {', '.join(a.name for a in va_assets)}. "
                f"The entity uses these methods to {verb} vendor electronic remote access:\n" + "\n".join(lines) + extra)
    if code == "CIP-003 R3":
        return (f"The CIP Senior Manager is {org.cip_senior_manager or '[not recorded]'}"
                + (f", in the role since {org.cip_senior_manager_since}." if org.cip_senior_manager_since else "."))
    if code == "CIP-003 R4":
        ds = db.query(Delegation).filter_by(org_id=org.id).order_by(Delegation.effective_on).all()
        if not ds:
            return "The CIP Senior Manager has not delegated authority."
        return "Delegations of CIP Senior Manager authority:\n" + "\n".join(
            f"{x.delegate_name}{', ' + x.delegate_title if x.delegate_title else ''}: {x.authority} "
            f"(effective {x.effective_on}{', revoked ' + str(x.revoked_on) if x.revoked_on else ''})" for x in ds)
    return ""


GENERATED = {
    "CIP-002 R1.3": [("02_assets.csv", "Asset list", "Assets containing low impact BCS, with connectivity flags.")],
    "CIP-002 R2": [("08_signoffs.csv", "Sign-off register", "Dated CIP Senior Manager approvals of the asset list, "
                    "with document hashes; signed copies under signoffs/.")],
    "CIP-003 R1.2": [("08_signoffs.csv", "Sign-off register", "Dated CIP Senior Manager approvals of the policy; "
                      "signed copies under signoffs/.")],
    "CIP-003 Att1 S2": [("02_assets.csv", "Asset list", "Physical security controls described per asset.")],
    "CIP-003 Att1 S3.1": [("02_assets.csv", "Asset list", "Electronic access controls described per asset.")],
    "CIP-003 Att1 S6.1": [
        ("03_vendor_remote_access.csv", "Vendor remote access register", "Each vendor access path and its 6.1 method."),
        ("04_vendor_sessions.csv", "Vendor session log", "Every recorded vendor session, logged or imported from "
         "VPN/remote-access logs, with approver."),
        ("09_findings.csv", "Findings register", "Sessions without approval and how each was resolved.")],
    "CIP-003 Att1 S6.2": [
        ("03_vendor_remote_access.csv", "Vendor remote access register", "Each vendor access path and its 6.2 method."),
        ("04_vendor_sessions.csv", "Vendor session log", "Session end reasons, including sessions terminated by the "
         "entity."),
        ("06_activity_log.csv", "Activity log", "Records of access paths being disabled and windows revoked.")],
    "CIP-003 Att1 S6.3": [("03_vendor_remote_access.csv", "Vendor remote access register",
                           "Each vendor access path and its 6.3 detection method."),
                          ("04_vendor_sessions.csv", "Vendor session log",
                           "Sessions flagged for known or suspected malicious communication.")],
    "CIP-003 R4": [("06_activity_log.csv", "Activity log", "Dated records of delegations added and revoked.")],
}


def workbook(db: Session, org: Organization) -> dict:
    statuses = {s.req.code: s for s in requirement_statuses(db, org)}
    narratives = {n.key: n for n in db.query(Narrative).filter(Narrative.org_id == org.id,
                                                                Narrative.key.like("rsaw:%")).all()}
    ev_by_req = defaultdict(list)
    for e in db.query(Evidence).filter_by(org_id=org.id).order_by(Evidence.performed_on.desc()).all():
        ev_by_req[e.requirement.code].append(e)
    open_findings = defaultdict(list)
    for x in db.query(Finding).filter_by(org_id=org.id, status="Open").all():
        if x.requirement_code:
            open_findings[x.requirement_code].append(x)
    sections = []
    for std, heading, codes in SECTIONS:
        items = []
        for code in codes:
            st = statuses.get(code)
            if not st:
                continue
            ev = ev_by_req.get(code, [])
            items.append(dict(code=code, st=st, focus=AUDITOR_FOCUS.get(code, ""),
                              narrative=narratives.get(f"rsaw:{code}"),
                              evidence=[e for e in ev if _in_period(e.performed_on, org)],
                              evidence_outside=[e for e in ev if not _in_period(e.performed_on, org)],
                              findings=open_findings.get(code, []), generated=GENERATED.get(code, [])))
        sections.append(dict(standard=std, heading=heading, reqs=items))
    return dict(org=org, sections=sections, today=date.today())
