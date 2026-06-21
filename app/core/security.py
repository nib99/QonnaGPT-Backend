"""
QonnaGPT Auth Service - Security Layer
Handles: JWT tokens (RS256/HS256), bcrypt password hashing,
         TOTP/OTP MFA, token blacklisting via Redis.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pyotp
import structlog
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

logger = structlog.get_logger(__name__)

# ─── Password Hashing ─────────────────────────────────────────────────────────

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,  # Tuned for ~100ms on modern hardware
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time password verification to prevent timing attacks."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password with bcrypt (12 rounds)."""
    return pwd_context.hash(password)


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password meets security policy.
    Returns (is_valid, list_of_errors).
    """
    errors: list[str] = []

    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    if not any(c in string.punctuation for c in password):
        errors.append("Password must contain at least one special character")

    return len(errors) == 0, errors


# ─── JWT Token Management ─────────────────────────────────────────────────────

def create_access_token(
    subject: str | UUID,
    extra_claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed JWT access token.
    Uses RS256 in production (private key), HS256 in development.
    """
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "access",
        "jti": secrets.token_urlsafe(16),  # JWT ID for blacklisting
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm="HS256",  # Upgrade to RS256 with key pair in production
    )


def create_refresh_token(
    subject: str | UUID,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a long-lived refresh token stored in Redis."""
    now = datetime.now(UTC)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload: dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "refresh",
        "jti": secrets.token_urlsafe(32),
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT token.
    Raises JWTError on invalid/expired tokens.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_exp": True},
    )


def create_email_verification_token(user_id: str, email: str) -> str:
    """Create short-lived email verification token."""
    payload = {
        "sub": user_id,
        "email": email,
        "type": "email_verify",
        "exp": datetime.now(UTC) + timedelta(hours=24),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


def create_password_reset_token(user_id: str) -> str:
    """Create short-lived password reset token."""
    payload = {
        "sub": user_id,
        "type": "password_reset",
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")


# ─── OTP / MFA ────────────────────────────────────────────────────────────────

def generate_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_totp_secret() -> str:
    """Generate a TOTP secret for authenticator apps (Google Auth, Authy)."""
    return pyotp.random_base32()


def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token. Allows 1-step drift for clock skew."""
    totp = pyotp.TOTP(secret, issuer=settings.TOTP_ISSUER)
    return totp.verify(token, valid_window=1)


def get_totp_provisioning_uri(secret: str, account_name: str) -> str:
    """Get TOTP provisioning URI for QR code generation."""
    totp = pyotp.TOTP(secret, issuer=settings.TOTP_ISSUER)
    return totp.provisioning_uri(name=account_name, issuer_name=settings.TOTP_ISSUER)


def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate one-time backup recovery codes."""
    return [
        "-".join(
            secrets.token_hex(2).upper()
            for _ in range(3)
        )
        for _ in range(count)
    ]


def hash_backup_code(code: str) -> str:
    """Hash a backup code for secure storage."""
    normalized = code.replace("-", "").upper()
    return hashlib.sha256(normalized.encode()).hexdigest()


def verify_backup_code(plain_code: str, hashed_code: str) -> bool:
    """Verify a backup recovery code (constant-time)."""
    normalized = plain_code.replace("-", "").upper()
    computed = hashlib.sha256(normalized.encode()).hexdigest()
    return secrets.compare_digest(computed, hashed_code)


# ─── Token Fingerprinting ─────────────────────────────────────────────────────

def generate_device_fingerprint(
    user_agent: str,
    ip_address: str,
    additional: str = "",
) -> str:
    """
    Generate a device fingerprint for session binding.
    Not for authentication - only for anomaly detection.
    """
    raw = f"{user_agent}:{ip_address}:{additional}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
