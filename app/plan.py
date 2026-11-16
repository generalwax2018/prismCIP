"""Builds the CIP-003 low impact cyber security plan from what's recorded in the app.

The output is a starting draft. Anything the app can't know is marked TODO so nobody signs a plan that
claims controls that don't exist.
"""
from datetime import date

from sqlalchemy.orm import Session

from .models import Asset, Delegation, Organization, VendorAccess

TODO = "TODO — describe before approval"


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
    return dict(org=org, today=date.today(), assets=assets, physical=physical, electronic=electronic,
                dialup=dialup, s6=s6, delegations=delegations, todos=todos, TODO=TODO,
                any_vendor_access=any(a.vendor_remote_access_allowed for a in assets))
