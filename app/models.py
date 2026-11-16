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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    vendor: Mapped[Vendor] = relationship(back_populates="access")
    asset: Mapped[Asset] = relationship(back_populates="vendor_access")
    sessions: Mapped[list["AccessSession"]] = relationship(back_populates="access", cascade="all, delete-orphan",
                                                           order_by="AccessSession.started_at.desc()")

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
    access: Mapped[VendorAccess] = relationship(back_populates="sessions")


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
