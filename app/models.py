"""Data model. Every record belongs to an Organization so the app can go multi-tenant later."""
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Column, Date, DateTime, ForeignKey, Integer, String, Table, Text
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
    account_review_months: Mapped[int] = mapped_column(Integer, default=3)
    oidc_issuer: Mapped[str | None] = mapped_column(String(300))
    oidc_client_id: Mapped[str | None] = mapped_column(String(300))
    oidc_client_secret: Mapped[str | None] = mapped_column(String(600))  # sealed with the server key
    oidc_domain: Mapped[str | None] = mapped_column(String(300), index=True)  # email domains this IdP may vouch for
    sso_required: Mapped[bool] = mapped_column(Boolean, default=False)
    # Hosted billing (only used when PRISMCIP_HOSTED is on). None = self-hosted, never gated.
    plan_status: Mapped[str | None] = mapped_column(String(20))  # trialing | active | past_due | canceled | unpaid
    trial_ends: Mapped[date | None] = mapped_column(Date)
    paid_through: Mapped[date | None] = mapped_column(Date)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(100), index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(100))
    billing_email: Mapped[str | None] = mapped_column(String(200))
    ai_enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # admin opt-in: drafts are sent to the AI API
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
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime)
    session_version: Mapped[int] = mapped_column(Integer, default=1)  # bump to sign out every session
    is_partner: Mapped[bool] = mapped_column(Boolean, default=False)  # may create utilities (consultants, G&Ts)
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
    contract_end: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="Active")  # Active | Offboarding | Offboarded
    offboarded_on: Mapped[date | None] = mapped_column(Date)
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
    # Locked once the item has gone into an exported package or a signed record: it can then only be superseded.
    locked_at: Mapped[datetime | None] = mapped_column(DateTime)
    locked_reason: Mapped[str | None] = mapped_column(String(300))
    superseded_by_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime)
    superseded_note: Mapped[str | None] = mapped_column(Text)
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
    # Hash chain (per organization): hash = SHA-256 over the previous hash and this entry's content.
    seq: Mapped[int | None] = mapped_column(Integer, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str | None] = mapped_column(String(64))
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime)



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



class PasswordReset(Base):
    """Single-use password reset link. Only a SHA-256 of the token is stored."""
    __tablename__ = "password_resets"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LoginAttempt(Base):
    """Sign-in attempts, for throttling. Kept 30 days."""
    __tablename__ = "login_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    email: Mapped[str] = mapped_column(String(200), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="password")  # password | mfa | forgot
    ok: Mapped[bool] = mapped_column(Boolean, default=False)



class Applicability(Base):
    """A requirement marked not applicable, with the reason. The decision is itself filed as evidence."""
    __tablename__ = "applicability"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"))
    reason: Mapped[str] = mapped_column(Text)
    decided_by: Mapped[str] = mapped_column(String(200))
    decided_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime)
    withdrawn_by: Mapped[str | None] = mapped_column(String(200))
    requirement: Mapped[Requirement] = relationship()



class Noncompliance(Base):
    """A possible noncompliance: what happened, why, the risk, the mitigation, and what was reported."""
    __tablename__ = "noncompliance"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    requirement_id: Mapped[int] = mapped_column(ForeignKey("requirements.id"))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    discovered_on: Mapped[date] = mapped_column(Date)
    discovered_how: Mapped[str] = mapped_column(String(60))
    started_on: Mapped[date | None] = mapped_column(Date)  # when the noncompliance began
    ended_on: Mapped[date | None] = mapped_column(Date)  # when compliance was restored
    cause_category: Mapped[str | None] = mapped_column(String(30))  # People | Process | Technology | Vendor | Other
    root_cause: Mapped[str | None] = mapped_column(Text)
    risk: Mapped[str | None] = mapped_column(String(20))  # Minimal | Moderate | Serious
    risk_rationale: Mapped[str | None] = mapped_column(Text)
    disposition: Mapped[str] = mapped_column(String(40), default="Not yet decided")
    submitted_on: Mapped[date | None] = mapped_column(Date)
    tracking_id: Mapped[str | None] = mapped_column(String(80))  # Regional Entity's reference
    status: Mapped[str] = mapped_column(String(20), default="Open")  # Open | Mitigating | Closed
    closed_on: Mapped[date | None] = mapped_column(Date)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    requirement: Mapped[Requirement] = relationship()
    steps: Mapped[list["MitigationStep"]] = relationship(back_populates="item", cascade="all, delete-orphan",
                                                         order_by="MitigationStep.id")


class MitigationStep(Base):
    __tablename__ = "mitigation_steps"
    id: Mapped[int] = mapped_column(primary_key=True)
    noncompliance_id: Mapped[int] = mapped_column(ForeignKey("noncompliance.id", ondelete="CASCADE"))
    text: Mapped[str] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(200))
    due_on: Mapped[date | None] = mapped_column(Date)
    completed_on: Mapped[date | None] = mapped_column(Date)
    item: Mapped[Noncompliance] = relationship(back_populates="steps")


audit_request_evidence = Table(
    "audit_request_evidence", Base.metadata,
    Column("request_id", ForeignKey("audit_requests.id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
)


class AuditRequest(Base):
    """An evidence request from the Regional Entity during an audit (RFI / data request)."""
    __tablename__ = "audit_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    ref: Mapped[str] = mapped_column(String(40))  # e.g. RFI-07
    received_on: Mapped[date] = mapped_column(Date)
    due_on: Mapped[date] = mapped_column(Date)
    requirement_id: Mapped[int | None] = mapped_column(ForeignKey("requirements.id"))
    request: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(20), default="Open")  # Open | In progress | Submitted | Closed
    response: Mapped[str | None] = mapped_column(Text)
    submitted_on: Mapped[date | None] = mapped_column(Date)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    requirement: Mapped[Requirement | None] = relationship()
    owner: Mapped[User | None] = relationship()
    evidence: Mapped[list[Evidence]] = relationship(secondary=audit_request_evidence)


class OffboardStep(Base):
    """A manual step in offboarding a vendor; the automatic checks are computed live."""
    __tablename__ = "offboard_steps"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    vendor_id: Mapped[int] = mapped_column(ForeignKey("vendors.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(40))
    done_at: Mapped[datetime | None] = mapped_column(DateTime)
    done_by: Mapped[str | None] = mapped_column(String(200))
    note: Mapped[str | None] = mapped_column(Text)


class AccountReview(Base):
    """Periodic review of every vendor account that can reach an asset."""
    __tablename__ = "account_reviews"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    started_by: Mapped[str] = mapped_column(String(200))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_by: Mapped[str | None] = mapped_column(String(200))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"))
    items: Mapped[list["AccountReviewItem"]] = relationship(back_populates="review", cascade="all, delete-orphan",
                                                            order_by="AccountReviewItem.id")


class AccountReviewItem(Base):
    __tablename__ = "account_review_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    review_id: Mapped[int] = mapped_column(ForeignKey("account_reviews.id", ondelete="CASCADE"))
    access_id: Mapped[int | None] = mapped_column(ForeignKey("vendor_access.id", ondelete="SET NULL"))
    label: Mapped[str] = mapped_column(String(300))  # vendor → asset (method)
    account: Mapped[str] = mapped_column(String(200))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    decision: Mapped[str | None] = mapped_column(String(10))  # keep | remove
    note: Mapped[str | None] = mapped_column(Text)
    review: Mapped[AccountReview] = relationship(back_populates="items")



class Membership(Base):
    """A person's access to one utility. User.org_id / role / can_sign mirror the membership they're working in."""
    __tablename__ = "memberships"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20), default="editor")
    can_sign: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user: Mapped[User] = relationship()
    org: Mapped[Organization] = relationship()


class ReadinessItem(Base):
    """Preparation for CIP-003-11 (effective July 1, 2029): one row per checklist item, per asset or org-wide."""
    __tablename__ = "readiness_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="Not started")  # Not started | Planned | In place | Not applicable
    method: Mapped[str | None] = mapped_column(Text)  # the control that will do it
    owner: Mapped[str | None] = mapped_column(String(200))
    target_date: Mapped[date | None] = mapped_column(Date)
    updated_by: Mapped[str | None] = mapped_column(String(200))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime)


class BillingEvent(Base):
    """Stripe webhook events already applied, so a retried delivery is applied once."""
    __tablename__ = "billing_events"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    kind: Mapped[str] = mapped_column(String(100))
    org_id: Mapped[int | None] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AiSuggestion(Base):
    """A drafted text from the AI service. Nothing reaches a plan or RSAW response until a person accepts it."""
    __tablename__ = "ai_suggestions"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    key: Mapped[str] = mapped_column(String(100), index=True)  # rsaw:<code> | plan:<section>
    body: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="Pending")  # Pending | Accepted | Discarded
    input_sha256: Mapped[str] = mapped_column(String(64))  # what was sent, for the record
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
