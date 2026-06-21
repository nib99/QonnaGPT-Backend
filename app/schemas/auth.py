"""
QonnaGPT Auth Service - Pydantic Schemas
Request validation and response serialization with strict typing.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

import phonenumbers
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.models.auth import MFAMethod, UserRole, UserStatus


# ─── Base Schemas ─────────────────────────────────────────────────────────────

class BaseSchema(BaseModel):
    model_config = {"from_attributes": True, "populate_by_name": True}


# ─── Phone Validation ─────────────────────────────────────────────────────────

def validate_ethiopian_phone(phone: str) -> str:
    """
    Validate and normalize Ethiopian phone numbers.
    Accepts: +251912345678, 0912345678, 912345678
    Returns: +251912345678 (E.164 format)
    """
    try:
        # Normalize local Ethiopian format
        if phone.startswith("09") or phone.startswith("07"):
            phone = "+251" + phone[1:]
        elif re.match(r"^[97]\d{8}$", phone):
            phone = "+251" + phone

        parsed = phonenumbers.parse(phone, "ET")
        if not phonenumbers.is_valid_number(parsed):
            raise ValueError("Invalid phone number")
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        raise ValueError("Invalid phone number format. Use +251XXXXXXXXX or 09XXXXXXXX")


PhoneNumber = Annotated[str, Field(min_length=9, max_length=20)]


# ─── Registration Schemas ──────────────────────────────────────────────────────

class UserRegisterRequest(BaseSchema):
    """Farmer registration payload."""
    phone_number: PhoneNumber
    full_name: str = Field(min_length=2, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str
    preferred_language: str = Field(default="om", pattern="^(om|am|en)$")
    role: UserRole = UserRole.FARMER
    email: EmailStr | None = None
    region: str | None = Field(default=None, max_length=100)
    woreda: str | None = Field(default=None, max_length=100)

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        return validate_ethiopian_phone(v)

    @field_validator("full_name")
    @classmethod
    def clean_name(cls, v: str) -> str:
        # Strip dangerous characters
        cleaned = re.sub(r"[<>\"'%;()&+]", "", v).strip()
        if len(cleaned) < 2:
            raise ValueError("Invalid name")
        return cleaned

    @model_validator(mode="after")
    def passwords_match(self) -> UserRegisterRequest:
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class UserRegisterResponse(BaseSchema):
    id: UUID
    phone_number: str
    full_name: str
    role: UserRole
    status: UserStatus
    phone_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Login Schemas ─────────────────────────────────────────────────────────────

class LoginRequest(BaseSchema):
    """Phone + password login."""
    phone_number: PhoneNumber
    password: str = Field(min_length=1, max_length=128)
    device_name: str | None = Field(default=None, max_length=255)

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        return validate_ethiopian_phone(v)


class MFAChallengeRequired(BaseSchema):
    """Returned when MFA is required after initial auth."""
    mfa_required: bool = True
    mfa_methods: list[MFAMethod]
    challenge_token: str  # Short-lived token to complete MFA
    message: str = "MFA verification required"


class MFAVerifyRequest(BaseSchema):
    """Complete MFA challenge."""
    challenge_token: str
    method: MFAMethod
    code: str = Field(min_length=6, max_length=8)


class TokenResponse(BaseSchema):
    """Successful authentication token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserPublicProfile


class RefreshTokenRequest(BaseSchema):
    refresh_token: str


class LogoutRequest(BaseSchema):
    refresh_token: str | None = None
    all_devices: bool = False  # Logout from all sessions


# ─── OTP / Verification Schemas ────────────────────────────────────────────────

class SendOTPRequest(BaseSchema):
    phone_number: PhoneNumber
    purpose: str = Field(pattern="^(phone_verify|password_reset|login_otp)$")

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        return validate_ethiopian_phone(v)


class VerifyOTPRequest(BaseSchema):
    phone_number: PhoneNumber
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    purpose: str = Field(pattern="^(phone_verify|password_reset|login_otp)$")

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        return validate_ethiopian_phone(v)


# ─── Password Management ──────────────────────────────────────────────────────

class PasswordChangeRequest(BaseSchema):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str

    @model_validator(mode="after")
    def passwords_match(self) -> PasswordChangeRequest:
        if self.new_password != self.confirm_new_password:
            raise ValueError("New passwords do not match")
        return self


class PasswordResetRequest(BaseSchema):
    phone_number: PhoneNumber
    otp_code: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        return validate_ethiopian_phone(v)

    @model_validator(mode="after")
    def passwords_match(self) -> PasswordResetRequest:
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


# ─── MFA Management ───────────────────────────────────────────────────────────

class EnableTOTPResponse(BaseSchema):
    secret: str
    provisioning_uri: str
    backup_codes: list[str]
    qr_code_base64: str | None = None


class VerifyTOTPSetupRequest(BaseSchema):
    """Confirm TOTP setup by verifying first code."""
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class DisableMFARequest(BaseSchema):
    method: MFAMethod
    confirmation_password: str


# ─── User Profile ─────────────────────────────────────────────────────────────

class UserPublicProfile(BaseSchema):
    """Safe user data to include in token responses."""
    id: UUID
    phone_number: str
    full_name: str
    email: str | None
    role: UserRole
    preferred_language: str
    phone_verified: bool
    mfa_enabled: bool
    region: str | None
    woreda: str | None

    model_config = {"from_attributes": True}


class UserDetailProfile(UserPublicProfile):
    """Full profile for authenticated user."""
    status: UserStatus
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime


# ─── Admin Schemas ────────────────────────────────────────────────────────────

class AdminUpdateUserRequest(BaseSchema):
    role: UserRole | None = None
    status: UserStatus | None = None
    region: str | None = None
    woreda: str | None = None
    organization_id: str | None = None


class AuditLogResponse(BaseSchema):
    id: UUID
    user_id: UUID | None
    action: str
    ip_address: str | None
    success: bool
    failure_reason: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Common Response Shapes ───────────────────────────────────────────────────

class MessageResponse(BaseSchema):
    message: str
    success: bool = True


class ErrorResponse(BaseSchema):
    detail: str
    code: str | None = None
    field: str | None = None


class PaginatedResponse(BaseSchema):
    items: list
    total: int
    page: int
    per_page: int
    pages: int
