"""
QonnaGPT Auth Service - Database Models
Production-grade SQLAlchemy 2.0 models with full typing.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.session import Base


# ─── Enumerations ─────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    FARMER = "farmer"
    EXTENSION_WORKER = "extension_worker"
    COOPERATIVE_MANAGER = "cooperative_manager"
    BANK_OFFICER = "bank_officer"
    INSURANCE_AGENT = "insurance_agent"
    RESEARCHER = "researcher"
    GOVERNMENT_OFFICIAL = "government_official"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class UserStatus(str, enum.Enum):
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    LOCKED = "locked"  # Too many failed login attempts


class MFAMethod(str, enum.Enum):
    TOTP = "totp"           # Authenticator app
    SMS_OTP = "sms_otp"    # SMS one-time password
    BIOMETRIC = "biometric" # Mobile biometric


class AuditAction(str, enum.Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    REGISTER = "register"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"
    TOKEN_REFRESHED = "token_refreshed"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ROLE_CHANGED = "role_changed"
    PROFILE_UPDATED = "profile_updated"
    BACKUP_CODE_USED = "backup_code_used"


# ─── Models ───────────────────────────────────────────────────────────────────

class User(Base):
    """
    Core user identity model.
    Phone number is the primary identifier for Ethiopian farmers
    (higher penetration than email in rural areas).
    """
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("phone_number", name="uq_users_phone"),
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_phone_status", "phone_number", "status"),
        Index("ix_users_role", "role"),
        Index("ix_users_created_at", "created_at"),
        {"schema": None},
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    phone_number: Mapped[str] = mapped_column(String(20), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Identity
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    preferred_language: Mapped[str] = mapped_column(
        String(10), default="om", nullable=False  # om=Oromo, am=Amharic, en=English
    )

    # Role & Status
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"), default=UserRole.FARMER, nullable=False
    )
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"),
        default=UserStatus.PENDING_VERIFICATION,
        nullable=False,
    )

    # Verification flags
    phone_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Security
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ABAC attributes for fine-grained access control
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)     # Ethiopian region
    woreda: Mapped[str | None] = mapped_column(String(100), nullable=True)     # District
    organization_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Metadata
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    mfa_configs: Mapped[list[MFAConfig]] = relationship(
        "MFAConfig", back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[UserSession]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User {self.phone_number} [{self.role.value}]>"

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked due to failed attempts."""
        if self.locked_until is None:
            return False
        return datetime.now(UTC) < self.locked_until

    @property
    def mfa_enabled(self) -> bool:
        """Check if any MFA method is active."""
        return any(m.is_active for m in self.mfa_configs)


class MFAConfig(Base):
    """
    Multi-factor authentication configuration per user.
    Supports multiple MFA methods simultaneously.
    """
    __tablename__ = "mfa_configs"
    __table_args__ = (
        UniqueConstraint("user_id", "method", name="uq_mfa_user_method"),
        Index("ix_mfa_configs_user_id", "user_id"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    method: Mapped[MFAMethod] = mapped_column(Enum(MFAMethod, name="mfa_method"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # TOTP fields
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)  # Encrypted at rest
    backup_codes_hashed: Mapped[list[str] | None] = mapped_column(ARRAY(String(64)), nullable=True)

    # Verification
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    user: Mapped[User] = relationship("User", back_populates="mfa_configs")

    def __repr__(self) -> str:
        return f"<MFAConfig user={self.user_id} method={self.method.value}>"


class UserSession(Base):
    """
    Active user sessions with device tracking.
    Enables multi-device session management and forced logout.
    """
    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_refresh_token_hash", "refresh_token_hash"),
        Index("ix_sessions_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Store hash of refresh token - never store raw tokens
    refresh_token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)

    # Device metadata
    device_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)

    # Session state
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    user: Mapped[User] = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<UserSession user={self.user_id} active={self.is_active}>"

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at


class AuditLog(Base):
    """
    Immutable audit trail for all security-relevant actions.
    Stored in append-only fashion for compliance.
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_user_id", "user_id"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_created_at", "created_at"),
        Index("ix_audit_ip_address", "ip_address"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, name="audit_action"), nullable=False
    )

    # Context
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    session_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)

    # Outcome
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Additional context stored as JSONB
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    user: Mapped[User | None] = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action.value} user={self.user_id} success={self.success}>"


class OTPCode(Base):
    """
    Short-lived OTP codes for phone verification and password reset.
    Deleted after use or expiry.
    """
    __tablename__ = "otp_codes"
    __table_args__ = (
        Index("ix_otp_phone_purpose", "phone_number", "purpose"),
        Index("ix_otp_expires_at", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    phone_number: Mapped[str] = mapped_column(String(20), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)  # SHA-256 hash of OTP
    purpose: Mapped[str] = mapped_column(
        String(50), nullable=False  # "phone_verify", "login", "password_reset"
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at

    @property
    def is_exhausted(self) -> bool:
        return self.attempts >= self.max_attempts
