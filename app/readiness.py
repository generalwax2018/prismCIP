"""CIP-003-11 readiness. CIP-003-11 was approved by FERC on March 19, 2026 and is effective July 1, 2029.
It folds the CIP-003-9 Section 6 vendor controls into Section 3 and adds, for all routable electronic access to or
from an asset with low impact BCS (and Shared Cyber Infrastructure that supports it): permit only necessary
access, detect known or suspected malicious communications in both directions, authenticate each user before
network access, and protect authentication information in transit. Summaries are paraphrased; work from the
standard itself on nerc.com."""
from datetime import date, timedelta

from sqlalchemy.orm import Session

from .models import Asset, Evidence, ReadinessItem, Requirement, VendorAccess

EFFECTIVE = date(2029, 7, 1)
STATUSES = ["Not started", "Planned", "In place", "Not applicable"]
WEAK = ("telnet", "http:", " http", "ftp", "vnc", "modem", "dial", "snmpv1", "snmp v1", "rsh")
STRONG = ("vpn", "ipsec", "tls", "ssl", "ssh", "https", "globalprotect", "anyconnect", "wireguard", "rdp gateway",
          "zero trust", "ztna")

ORG_ITEMS = [
    ("sci", "Scope", "Identify Shared Cyber Infrastructure",
     "List the shared or virtual infrastructure (hypervisors, shared network gear, storage) that supports low impact "
     "BCS. It comes into scope for Section 3 alongside the assets."),
    ("plan", "R2 / Att. 1", "Rewrite the cyber security plan(s) for the new Section 3",
     "Section 6 goes away and its vendor controls move into Section 3. Plan text that cites Section 6 needs to move."),
    ("ir", "Att. 1 S4", "Tie detected malicious communications to incident response",
     "Detections under the new 3.1.2 should feed the Cyber Security Incident response plan; say how in the plan."),
    ("budget", "Planning", "Budget and order equipment",
     "Detection and authentication at every site can need new hardware. Lead times were a problem for CIP-012; order early."),
]
ASSET_ITEMS = [
    ("3.1.1", "Permit only necessary access", "Only the inbound and outbound access you've decided is necessary."),
    ("3.1.2", "Detect malicious communications",
     "Detect known or suspected malicious traffic in both directions, for all access (not only vendors)."),
    ("3.1.3", "Authenticate each user first",
     "Authenticate every user before they reach the network holding the low impact BCS."),
    ("3.1.4", "Protect credentials in transit",
     "Protect user authentication information between the outside system and the authenticator or the asset."),
    ("3.1.5", "Determine vendor access", "Methods for knowing when vendors have electronic access (was 6.1)."),
    ("3.1.6", "Disable vendor access", "Methods for disabling vendor electronic access (was 6.2)."),
    ("3.2", "Authenticate dial-up", "Authenticate dial-up connectivity, per system capability."),
]
TITLES = {k: t for k, _c, t, _s in ORG_ITEMS} | {k: t for k, t, _s in ASSET_ITEMS}


def applies(asset: Asset, key: str) -> bool:
    if key == "3.2":
        return asset.dialup
    if key in ("3.1.5", "3.1.6"):
        return asset.routable_external and (asset.vendor_remote_access_allowed or bool(asset.vendor_access))
    return asset.routable_external


def hints(db: Session, asset: Asset) -> dict[str, tuple[str, str]]:
    """What PrismCIP already knows that bears on each item: (text, tone) with tone ok | warn | neutral."""
    out: dict[str, tuple[str, str]] = {}
    paths = [p for p in asset.vendor_access if p.status == "Enabled"] or list(asset.vendor_access)
    s31 = db.query(Requirement).filter_by(code="CIP-003 Att1 S3.1").first()
    fw = None
    if s31:
        fw = (db.query(Evidence).filter(Evidence.org_id == asset.org_id, Evidence.asset_id == asset.id,
                                        Evidence.requirement_id == s31.id, Evidence.title.like("Firewall rule review%"),
                                        Evidence.superseded_at.is_(None))
              .order_by(Evidence.performed_on.desc()).first())
    if fw and fw.performed_on >= date.today() - timedelta(days=455):
        out["3.1.1"] = (f"Firewall rule review on file from {fw.performed_on}. The same rule set must now justify "
                        "outbound access too.", "ok")
    elif asset.electronic_access_control:
        out["3.1.1"] = ("Today's Section 3 control is described; check it limits outbound as well as inbound.", "neutral")
    detect = [p for p in paths if p.detect_method]
    if detect:
        out["3.1.2"] = (f"{len(detect)} vendor path(s) have a 6.3 detection method. 3.1.2 widens that to all traffic "
                        "(staff, SCADA polling, everything routable).", "warn")
    vpnish = [p for p in paths if any(w in (p.access_method or "").lower() for w in STRONG)]
    weak = [p for p in paths if any(w in (p.access_method or "").lower() for w in WEAK)]
    if any(p.sessions for p in paths):
        out["3.1.3"] = ("Vendor sign-ins are already logged here, so vendors authenticate. Confirm staff and "
                        "machine-to-machine paths do too.", "neutral")
    if weak:
        out["3.1.4"] = ("Clear-text or modem method on: " + ", ".join(f"{p.vendor.name} ({p.access_method})"
                                                                     for p in weak), "warn")
    elif vpnish:
        out["3.1.4"] = ("Vendor paths use an encrypted method (" + ", ".join(sorted({p.access_method for p in vpnish}))
                        + ").", "ok")
    if paths:
        for k, attr, was in (("3.1.5", "determine_method", "6.1"), ("3.1.6", "disable_method", "6.2")):
            missing = [p.vendor.name for p in paths if not getattr(p, attr)]
            out[k] = ((f"Carries over from {was}: every vendor path has a method.", "ok") if not missing else
                      (f"No {was} method yet for: {', '.join(missing)}.", "warn"))
    return out


def load(db: Session, org_id: int) -> dict:
    rows = db.query(ReadinessItem).filter_by(org_id=org_id).all()
    by = {(r.asset_id, r.key): r for r in rows}
    assets = db.query(Asset).filter_by(org_id=org_id).order_by(Asset.name).all()
    org_rows = [dict(key=k, code=c, title=t, summary=s, row=by.get((None, k))) for k, c, t, s in ORG_ITEMS]
    per_asset = []
    for a in assets:
        h = hints(db, a)
        items = [dict(key=k, title=t, summary=s, row=by.get((a.id, k)), hint=h.get(k)) for k, t, s in ASSET_ITEMS
                 if applies(a, k)]
        per_asset.append(dict(asset=a, rows=items))
    counted = [i["row"] for i in org_rows] + [i["row"] for pa in per_asset for i in pa["rows"]]
    total = sum(1 for r in counted if not (r and r.status == "Not applicable"))
    done = sum(1 for r in counted if r and r.status == "In place")
    planned = sum(1 for r in counted if r and r.status == "Planned")
    overdue = [r for r in counted if r and r.target_date and r.target_date < date.today()
               and r.status in ("Not started", "Planned")]
    return dict(org_rows=org_rows, per_asset=per_asset, total=total, done=done, planned=planned, overdue=overdue,
                days_left=(EFFECTIVE - date.today()).days, effective=EFFECTIVE,
                out_of_scope=[a for a in assets if not a.routable_external and not a.dialup])


def summary(db: Session, org_id: int) -> dict:
    d = load(db, org_id)
    return dict(total=d["total"], done=d["done"], planned=d["planned"], overdue=len(d["overdue"]),
                days_left=d["days_left"], effective=d["effective"])
