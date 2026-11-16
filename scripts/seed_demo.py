"""Load a demo co-op so you can show PrismCIP to a prospect. Run: python -m scripts.seed_demo
Login afterwards: demo@prismcip.local / demo-password-123
"""
from datetime import date, timedelta

from app.auth import hash_password
from app.catalog import seed_requirements
from app.db import Base, SessionLocal, engine
from datetime import datetime

from app.models import (AccessApproval, AccessSession, Asset, AuditLog, Delegation, Evidence, Organization,
                        Requirement, User, Vendor, VendorAccess, utcnow)


def main():
    Base.metadata.create_all(engine)
    db = SessionLocal()
    seed_requirements(db)
    if db.query(User).filter_by(email="demo@prismcip.local").first():
        print("Demo data already loaded.")
        return
    org = Organization(name="High Plains Electric Cooperative", ncr_id="NCR99999", regional_entity="WECC",
                       registered_functions="DP, TO, GO", cip_senior_manager="Dana Ortiz, General Manager",
                       cip_senior_manager_since=date(2024, 6, 1), ignored_accounts="it-admin",
                       audit_id="WECC-NCR99999-20270315", audit_period_start=date(2024, 3, 15),
                       audit_period_end=date(2027, 3, 14))
    db.add(org)
    db.flush()
    db.add(User(org_id=org.id, email="demo@prismcip.local", name="Demo Admin", role="admin", can_sign=True,
                password_hash=hash_password("demo-password-123")))
    db.add(User(org_id=org.id, email="dana@prismcip.local", name="Dana Ortiz", role="viewer", can_sign=True,
                password_hash=hash_password("demo-password-123")))
    db.add(Delegation(org_id=org.id, delegate_name="Chris Lee", delegate_title="Operations Manager",
                      authority="Approve CIP-002 R2 asset list reviews", effective_on=date(2025, 1, 6)))
    north = Asset(org_id=org.id, name="North Substation", asset_type="Substation", location="Weld County, CO",
                  routable_external=True, vendor_remote_access_allowed=True,
                  physical_access_control="Perimeter fence with keyed gate; control house door on card reader; "
                                          "keys issued by Operations Manager.",
                  electronic_access_control="Fortinet firewall at control house. Inbound permitted only from "
                                            "SCADA master (DNP3/TCP 20000) and vendor VPN zone; all else denied.")
    plant = Asset(org_id=org.id, name="Prairie Wind Farm", asset_type="Generation", location="Logan County, CO",
                  routable_external=True, vendor_remote_access_allowed=True, dialup=True,
                  physical_access_control="Gated site, padlocked substation yard, O&M building alarmed.")
    ctrl = Asset(org_id=org.id, name="Main Office Control Room", asset_type="Control Center",
                 location="Sterling, CO", physical_access_control="Badge access, visitor log.")
    db.add_all([north, plant, ctrl])
    db.flush()
    relay = Vendor(org_id=org.id, name="Relay Pros LLC", contact="support@relaypros.example",
                   services="Protective relay settings and firmware")
    oem = Vendor(org_id=org.id, name="Turbine OEM Remote Ops", contact="noc@oem.example",
                 services="Turbine controller monitoring")
    db.add_all([relay, oem])
    db.flush()
    p1 = VendorAccess(org_id=org.id, vendor_id=relay.id, asset_id=north.id, access_method="Client VPN",
                      determine_method="Vendor opens a ticket; VPN account enabled only for the approved window. "
                                       "Firewall VPN log reviewed weekly.",
                      disable_method="VPN account disabled after each session; operator can terminate active "
                                     "tunnel from firewall console.",
                      detect_method="IPS profile and botnet C2 blocking on the vendor VPN zone; alerts emailed "
                                    "to IT and the SOC.", approved_by="Dana Ortiz", approved_on=date(2026, 3, 20),
                      accounts="relaypros-jalvarez")
    p2 = VendorAccess(org_id=org.id, vendor_id=oem.id, asset_id=plant.id, access_method="Cellular modem",
                      determine_method="OEM portal session report pulled monthly.", accounts="oem-noc")
    db.add_all([p1, p2])
    db.flush()
    now = utcnow()
    db.add(AccessSession(org_id=org.id, access_id=p1.id, vendor_person="J. Alvarez", purpose="Relay firmware 3.2",
                         approved_by="chris.lee", started_at=now - timedelta(days=12, hours=3),
                         ended_at=now - timedelta(days=12, hours=1), ended_by="chris.lee", end_reason="Completed"))
    db.add(AccessSession(org_id=org.id, access_id=p2.id, vendor_person="OEM NOC", purpose="Controller fault review",
                         approved_by="chris.lee", started_at=now - timedelta(hours=2)))
    db.add(AccessApproval(org_id=org.id, access_id=p1.id, starts_at=datetime(2026, 11, 2, 14, 30),
                          ends_at=datetime(2026, 11, 2, 18, 0), purpose="Relay firmware 3.1 at North Sub",
                          ticket="CHG-4471", approved_by="chris.lee"))
    reqs = {r.code: r for r in db.query(Requirement).all()}
    for code, title, when in [
        ("CIP-002 R1.3", "Asset identification worksheet", date(2026, 2, 10)),
        ("CIP-002 R2", "Asset list review signed by delegate", date(2025, 9, 15)),
        ("CIP-003 R1.2", "Low impact policy v4 incl. vendor remote access", date(2026, 3, 25)),
        ("CIP-003 Att1 S1", "Security awareness bulletin", date(2025, 10, 1)),
        ("CIP-003 Att1 S3.1", "North Sub firewall rule export", date(2026, 3, 1)),
        ("CIP-003 Att1 S4", "Incident response plan v3", date(2025, 5, 1)),
        ("CIP-003 Att1 S4.5", "Tabletop exercise report", date(2023, 8, 20)),
        ("CIP-003 R3", "CIP Senior Manager designation memo", date(2024, 6, 1)),
    ]:
        db.add(Evidence(org_id=org.id, requirement_id=reqs[code].id, title=title, performed_on=when,
                        uploaded_by="demo@prismcip.local"))
    db.add(AuditLog(org_id=org.id, actor="system", action="demo_loaded", detail="Demo data"))
    db.commit()
    print("Loaded. Sign in as demo@prismcip.local / demo-password-123")
    print("Try Remote access → Import sessions with samples/fortigate_vpn_events.log")


if __name__ == "__main__":
    main()
