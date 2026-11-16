"""Data model. Every record belongs to an Organization so the app can go multi-tenant later."""
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    ncr_id: Mapped[str | None] = mapped_column(String(50))  # NERC Compliance Registry ID
    regional_entity: Mapped[str | None] = mapped_column(String(50))
    registered_functions: Mapped[str | None] = mapped_column(String(200))  # e.g. "DP, GO, GOP"
    cip_senior_manager: Mapped[str | None] = mapped_column(String(200))
    cip_senior_manager_since: Mapped[date | None] = mapped_column(Date)
    audit_id: Mapped[str | None] = mapped_column(String(80))
    audit_period_start: Mapped[date | None] = mapped_column(Date)
    audit_period_end: Mapped[date | None] = mapped_column(Date)
    ignored_accounts: Mapped[str | None] = mapped_column(Text)  # comma/newline list: staff accounts that aren't vendors
    ingest_token_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(20), default="editor")  # admin | editor | viewer
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    can_sign: Mapped[bool] = mapped_column(Boolean, default=False)  # CIP Senior Manager or a delegate
    notify: Mapped[bool] = mapped_column(Boolean, default=True)  # receive reminder emails
    totp_secret: Mapped[str | None] = mapped_column(String(200))  # sealed with the server key, never plain
    totp_last_step: Mapped[int | None] = mapped_column(Integer)  # blocks replay of a code already used
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    org: Mapped[Organization] = relationship()


class Delegation(Base):
    """CIP-003 R4: delegations of CIP Senior Manager authority."""
    __tablename__ = "delegations"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    delegate_name: Mapped[str] = mapped_column(String(200))
    delegate_title: Mapped[str | None] = mapped_column(String(200))
    authority: Mapped[str] = mapped_column(Text)
    effective_on: Mapped[date] = mapped_column(Date)
    revoked_on: Mapped[date | None] = mapped_column(Date)


class Asset(Base):
    """An asset (site) that contains low impact BES Cyber Systems, per CIP-002 R1.3."""
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(200))
    asset_type: Mapped[str] = mapped_column(String(50))  # Substation | Generation | Control Center | Other
    location: Mapped[str | None] = mapped_column(String(300))
    impact_rating: Mapped[str] = mapped_column(String(20), default="Low")
    routable_external: Mapped[bool] = mapped_column(Boolean, default=False)  # routable protocol to outside
    dialup: Mapped[bool] = mapped_column(Boolean, default=False)
    vendor_remote_access_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    electronic_access_control: Mapped[str | None] = mapped_column(Text)  # Section 3.1 description
    physical_access_control: Mapped[str | None] = mapped_column(Text)  # Section 2 description
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    vendor_access: Mapped[list["VendorAccess"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Vendor(Base):
    __tablename__ = "vendors"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(200))
    contact: Mapped[str | None] = mapped_column(String(300))
    services: Mapped[str | None] = mapped_column(Text)
    portal_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    portal_expires: Mapped[date | None] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    access: Mapped[list["VendorAccess"]] = relationship(back_populates="vendor", cascade="all, delete-orphan")


class VendorAccess(Base):
    """A vendor electronic remote access path into an asset — the core of Attachment 1, Section 6."""
    __tablename__ = "vendor_access"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    access_method: Mapped[str] = mapped_column(String(100))  # VPN, jump host, vendor remote tool, modem...
    determine_method: Mapped[str | None] = mapped_column(Text)  # 6.1
    disable_method: Mapped[str | None] = mapped_column(Text)  # 6.2
    detect_method: Mapped[str | None] = mapped_column(Text)  # 6.3
    status: Mapped[str] = mapped_column(String(20), default="Enabled")  # Enabled | Disabled
    approved_by: Mapped[str | None] = mapped_column(String(200))
    approved_on: Mapped[date | None] = mapped_column(Date)
    accounts: Mapped[str | None] = mapped_column(Text)  # VPN / remote tool usernames used on this path
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    vendor: Mapped[Vendor] = relationship(back_populates="access")
    asset: Mapped[Asset] = relationship(back_populates="vendor_access")
    sessions: Mapped[list["AccessSession"]] = relationship(back_populates="access", cascade="all, delete-orphan",
                                                           order_by="AccessSession.started_at.desc()")
    approvals: Mapped[list["AccessApproval"]] = relationship(back_populates="access", cascade="all, delete-orphan",
                                                             order_by="AccessApproval.starts_at.desc()")

    @property
    def account_list(self) -> list[str]:
        import re
        return [a.strip().lower() for a in re.split(r"[,\n;]+", self.accounts or "") if a.strip()]

    @property
    def section6_complete(self) -> bool:
        return all([self.determine_method, self.disable_method, self.detect_method])


class AccessSession(Base):
    """One vendor remote session — evidence that access is determined (6.1) and can be disabled (6.2)."""
    __tablename__ = "access_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    access_id: Mapped[int] = mapped_column(ForeignKey("vendor_access.id"))
    vendor_person: Mapped[str] = mapped_column(String(200))
    purpose: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str | None] = mapped_column(String(200))
    started_at: Mapped[datetime] = mapped_column(DateTime)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime)
    ended_by: Mapped[str | None] = mapped_column(String(200))
    end_reason: Mapped[str | None] = mapped_column(String(200))  # Completed | Terminated by entity | Suspicious
    malicious_activity_noted: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(20), default="manual")  # manual | import
    external_key: Mapped[str | None] = mapped_column(String(64), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    account: Mapped[str | None] = mapped_column(String(200))
    import_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id", ondelete="SET NULL"))
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("access_approvals.id", ondelete="SET NULL"))
    access: Mapped[VendorAccess] = relationship(back_populates="sessions")


class AccessApproval(Base):
    """An approved window for vendor remote access. Imported sessions are checked against these."""
    __tablename__ = "access_approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    access_id: Mapped[int] = mapped_column(ForeignKey("vendor_access.id"))
    starts_at: Mapped[datetime] = mapped_column(DateTime)
    ends_at: Mapped[datetime] = mapped_column(DateTime)
    purpose: Mapped[str] = mapped_column(Text)
    ticket: Mapped[str | None] = mapped_column(String(100))
    approved_by: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="Approved")  # Requested | Approved | Denied
    requested_by: Mapped[str | None] = mapped_column(String(200))  # vendor person when it came from the portal
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    access: Mapped[VendorAccess] = relationship(back_populates="approvals")


class ImportBatch(Base):
    __tablename__ = "import_batches"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    by: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(50))  # fortigate | csv | api
    file_name: Mapped[str | None] = mapped_column(String(300))
    sha256: Mapped[str | None] = mapped_column(String(64))
    records: Mapped[int] = mapped_column(Integer, default=0)
    sessions_new: Mapped[int] = mapped_column(Integer, default=0)
    sessions_matched: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    findings_new: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Base):
    """Something an import (or a check) found that a person must look at: e.g. a vendor session with no approval."""
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    kind: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))  # high | medium | low
    title: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str | None] = mapped_column(Text)
    requirement_code: Mapped[str | None] = mapped_column(String(50))
    access_id: Mapped[int | None] = mapped_column(ForeignKey("vendor_access.id", ondelete="SET NULL"))
    session_id: Mapped[int | None] = mapped_column(ForeignKey("access_sessions.id", ondelete="SET NULL"))
    dedupe_key: Mapped[str | None] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(20), default="Open")  # Open | Resolved
    resolution: Mapped[str | None] = mapped_column(Text)
    resolved_by: Mapped[str | None] = mapped_column(String(200))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    access: Mapped[VendorAccess | None] = relationship()


class Signoff(Base):
    """A CIP Senior Manager (or delegate) approval of a document, with the document's hash frozen at request time."""
    __tablename__ = "signoffs"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    kind: Mapped[str] = mapped_column(String(30))  # policy | asset_review | plan | other
    title: Mapped[str] = mapped_column(String(300))
    requirement_id: Mapped[int | None] = mapped_column(ForeignKey("requirements.id"))
    file_name: Mapped[str | None] = mapped_column(String(300))
    stored_name: Mapped[str | None] = mapped_column(String(300))
    sha256: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(200))
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    signer_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default="Pending")  # Pending | Approved | Rejected
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    signature_name: Mapped[str | None] = mapped_column(String(200))
    decision_note: Mapped[str | None] = mapped_column(Text)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    signer: Mapped["User"] = relationship(foreign_keys=[signer_id])
    requirement: Mapped["Requirement | None"] = relationship()


class ReminderLog(Base):
    __tablename__ = "reminder_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    key: Mapped[str] = mapped_column(String(200), index=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    recipients: Mapped[str] = mapped_column(Text)


class Narrative(Base):
    """Free text the entity writes: RSAW responses (key rsaw:<code>) and plan sections (key plan:<section>)."""
    __tablename__ = "narratives"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    key: Mapped[str] = mapped_column(String(100), index=True)
    body: Mapped[str] = mapped_column(Text)
    updated_by: Mapped[str] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Requirement(Base):
    """Seeded catalog of requirements. Shared across orgs."""
    __tablename__ = "requirements"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)  # e.g. CIP-003-9 Att1 S6.1
    standard: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text)
    evidence_hint: Mapped[str] = mapped_column(Text)
    cadence_months: Mapped[int | None] = mapped_column(Integer)  # None = ongoing / event-driven
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    section6: Mapped[bool] = mapped_column(Boolean, default=False)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    performed_on: Mapped[date] = mapped_column(Date)  # date the activity happened (drives due dates)
    file_name: Mapped[str | None] = mapped_column(String(300))
    stored_name: Mapped[str | None] = mapped_column(String(300))
    sha256: Mapped[str | None] = mapped_column(String(64))
    uploaded_by: Mapped[str] = mapped_column(String(200))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    requirement: Mapped[Requirement] = relationship()
    asset: Mapped[Asset | None] = relationship()


class AuditLog(Base):
    """Append-only activity trail. The app never updates or deletes these rows."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str | None] = mapped_column(Text)



class ProgramRecord(Base):
    """Structured records for the recurring Attachment 1 programs. Each one is also filed as evidence.
    kind: awareness (S1) | exercise (S4.5, and S4.6 when the plan update is recorded) | transient (S5)."""
    __tablename__ = "program_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    kind: Mapped[str] = mapped_column(String(20))
    performed_on: Mapped[date] = mapped_column(Date)
    title: Mapped[str] = mapped_column(String(300))
    method: Mapped[str | None] = mapped_column(String(200))  # awareness: email/briefing; exercise: tabletop/drill/real
    audience: Mapped[str | None] = mapped_column(Text)  # recipients or participants
    details: Mapped[str | None] = mapped_column(Text)  # scenario + lessons, or device / scan details
    device_owner: Mapped[str | None] = mapped_column(String(20))  # transient: entity | vendor | removable media
    result: Mapped[str | None] = mapped_column(String(40))  # transient: clean | malware found | not scanned
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    plan_updated_on: Mapped[date | None] = mapped_column(Date)  # exercise: S4.6
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    update_evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    asset: Mapped[Asset | None] = relationship()
