"""Builds the CIP-003 low impact cyber security plan from what's recorded in the app.

The output is a starting draft. Anything the app can't know is marked TODO so nobody signs a plan that
claims controls that don't exist.
"""
from datetime import date

from sqlalchemy.orm import Session

from .models import Asset, Delegation, Narrative, Organization, VendorAccess

TODO = "TODO — describe before approval"

# Narrative sections the entity writes itself; everything else in the plan comes from records.
SECTIONS = [
    ("s1_method", "Section 1 — How cyber security practices are reinforced",
     "e.g. A security awareness bulletin is emailed to all staff with access to these assets each March, and the "
     "topic is covered in the annual safety meeting. Records are kept by Operations."),
    ("s3_dialup_auth", "Section 3.2 — How dial-up connectivity is authenticated",
     "e.g. The RTU modem at Prairie Wind Farm requires a password and dial-back to a fixed number."),
    ("s4_plan_ref", "Section 4 — Incident response plan document",
     "e.g. 'Cyber Security Incident Response Plan v3', SharePoint › Compliance › CIP. Owner: IT Manager."),
    ("s5_tca_entity", "Section 5 — Transient Cyber Assets the entity manages",
     "e.g. Two dedicated relay laptops with antivirus and application allowlisting, updated monthly, kept in "
     "the Operations office."),
    ("s5_tca_third", "Section 5 — Transient Cyber Assets managed by vendors",
     "e.g. Before connecting, vendor laptops are scanned on the kiosk, or the vendor shows current antivirus and "
     "patch status; the technician records it on the site checklist."),
    ("s5_rm", "Section 5 — Removable Media",
     "e.g. USB drives are scanned on the kiosk in the Operations office before use on any low impact BCS."),
    ("cip_exceptional", "CIP Exceptional Circumstances",
     "e.g. The CIP Senior Manager or delegate declares a CIP Exceptional Circumstance by email to Compliance; "
     "controls are restored and the event documented within 30 days."),
]


def build_plan(db: Session, org: Organization) -> dict:
    assets = db.query(Asset).filter_by(org_id=org.id).order_by(Asset.name).all()
    paths = db.query(VendorAccess).filter_by(org_id=org.id).all()
    paths.sort(key=lambda p: (p.asset.name, p.vendor.name))
    delegations = (db.query(Delegation).filter_by(org_id=org.id, revoked_on=None)
                   .order_by(Delegation.effective_on).all())
    todos = 0

    def val(x):
        nonlocal todos
        if not x:
            todos += 1
            return None
        return x

    physical = [(a, val(a.physical_access_control)) for a in assets]
    electronic = [(a, val(a.electronic_access_control) if a.routable_external else "No routable "
                   "communication crosses the asset boundary to or from the low impact BCS.") for a in assets]
    dialup = [a for a in assets if a.dialup]
    s6 = [dict(p=p, determine=val(p.determine_method), disable=val(p.disable_method),
               detect=val(p.detect_method)) for p in paths]
    if not org.cip_senior_manager:
        todos += 1
    written = {n.key[5:]: n.body for n in db.query(Narrative).filter(Narrative.org_id == org.id,
                                                                     Narrative.key.like("plan:%")).all() if n.body}
    needed = [k for k, _, _ in SECTIONS if not (k == "s3_dialup_auth" and not dialup)]
    todos += sum(1 for k in needed if k not in written)
    return dict(org=org, today=date.today(), assets=assets, physical=physical, electronic=electronic,
                dialup=dialup, s6=s6, delegations=delegations, todos=todos, TODO=TODO, text=written,
                any_vendor_access=any(a.vendor_remote_access_allowed for a in assets))
