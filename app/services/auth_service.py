"""
QonnaGPT Auth Service - Authentication Business Logic
Clean service layer separating domain logic from HTTP concerns.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    generate_backup_codes,
    generate_otp,
    generate_totp_secret,
    get_password_hash,
    get_totp_provisioning_uri,
    hash_backup_code,
    verify_backup_code,
    verify_password,
    verify_totp,
    validate_password_strength,
)
from app.models.auth import AuditAction, AuditLog, MFAConfig, MFAMethod, OTPCode, User, UserRole, UserSession, UserStatus
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserPublicProfile,
    UserRegisterRequest,
)
from app.utils.redis_client import AuthRedisService

logger = structlog.get_logger(__name__)


class AuthError(Exception):
    """Base auth service exception."""
    def __init__(self, message: str, code: str = "AUTH_ERROR", status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class InvalidCredentialsError(AuthError):
    def __init__(self):
        super().__init__("Invalid phone number or password", "INVALID_CREDENTIALS", 401)


class AccountLockedError(AuthError):
    def __init__(self, locked_until: datetime):
        super().__init__(
            f"Account locked until {locked_until.isoformat()}",
            "ACCOUNT_LOCKED",
            423,
        )
        self.locked_until = locked_until


class MFARequiredError(AuthError):
    def __init__(self, challenge_token: str, methods: list[MFAMethod]):
        super().__init__("MFA verification required", "MFA_REQUIRED", 202)
        self.challenge_token = challenge_token
        self.methods = methods


class PhoneNotVerifiedError(AuthError):
    def __init__(self):
        super().__init__("Phone number not verified", "PHONE_NOT_VERIFIED", 403)


class UserNotFoundError(AuthError):
    def __init__(self):
        super().__init__("User not found", "USER_NOT_FOUND", 404)


class DuplicatePhoneError(AuthError):
    def __init__(self):
        super().__init__("Phone number already registered", "DUPLICATE_PHONE", 409)


class InvalidOTPError(AuthError):
    def __init__(self):
        super().__init__("Invalid or expired OTP code", "INVALID_OTP", 401)


class WeakPasswordError(AuthError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors), "WEAK_PASSWORD", 400)
        self.errors = errors


def _hash_token(token: str) -> str:
    """SHA-256 hash for secure token storage."""
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    """
    Core authentication service implementing all auth flows.
    Injected with db session and redis service.
    """

    def __init__(self, db: AsyncSession, redis: AuthRedisService) -> None:
        self.db = db
        self.redis = redis

    # ─── Registration ─────────────────────────────────────────────────────────

    async def register(
        self,
        data: UserRegisterRequest,
        ip_address: str | None = None,
    ) -> User:
        """
        Register a new user.
        1. Check password strength
        2. Check phone uniqueness
        3. Create user with hashed password
        4. Send OTP for phone verification
        """
        # Validate password policy
        is_valid, errors = validate_password_strength(data.password)
        if not is_valid:
            raise WeakPasswordError(errors)

        # Check for duplicate phone
        existing = await self.db.execute(
            select(User).where(User.phone_number == data.phone_number)
        )
        if existing.scalar_one_or_none():
            raise DuplicatePhoneError()

        # Create user
        user = User(
            phone_number=data.phone_number,
            email=data.email,
            hashed_password=get_password_hash(data.password),
            full_name=data.full_name,
            preferred_language=data.preferred_language,
            role=data.role,
            status=UserStatus.PENDING_VERIFICATION,
            region=data.region,
            woreda=data.woreda,
        )

        self.db.add(user)
        await self.db.flush()  # Get the ID without committing

        # Audit log
        await self._audit(
            user_id=user.id,
            action=AuditAction.REGISTER,
            success=True,
            ip_address=ip_address,
            metadata={"phone": data.phone_number, "role": data.role.value},
        )

        logger.info(
            "user_registered",
            user_id=str(user.id),
            phone=data.phone_number,
            role=data.role.value,
        )

        return user

    # ─── Login Flow ───────────────────────────────────────────────────────────

    async def login(
        self,
        data: LoginRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_fingerprint: str | None = None,
    ) -> TokenResponse | dict:
        """
        Authenticate a user via phone + password.
        Returns tokens directly OR an MFA challenge if MFA is enabled.
        """
        # Load user with MFA configs
        result = await self.db.execute(
            select(User)
            .where(User.phone_number == data.phone_number)
            .options(selectinload(User.mfa_configs))
        )
        user = result.scalar_one_or_none()

        # Constant-time failure path to prevent user enumeration
        if not user:
            # Still hash to prevent timing attack
            get_password_hash("dummy_password_to_normalize_timing")
            await self._audit(
                action=AuditAction.LOGIN_FAILED,
                success=False,
                ip_address=ip_address,
                failure_reason="user_not_found",
                metadata={"phone": data.phone_number},
            )
            raise InvalidCredentialsError()

        # Check lockout
        if user.is_locked:
            raise AccountLockedError(user.locked_until)

        # Verify password
        if not verify_password(data.password, user.hashed_password):
            await self._handle_failed_login(user, ip_address)
            raise InvalidCredentialsError()

        # Check account status
        if user.status == UserStatus.SUSPENDED:
            raise AuthError("Account suspended. Contact support.", "ACCOUNT_SUSPENDED", 403)
        if user.status == UserStatus.DEACTIVATED:
            raise AuthError("Account deactivated.", "ACCOUNT_DEACTIVATED", 403)

        # Check phone verification
        if not user.phone_verified:
            raise PhoneNotVerifiedError()

        # Check MFA
        active_mfa = [m for m in user.mfa_configs if m.is_active]
        if active_mfa:
            return await self._create_mfa_challenge(user, active_mfa)

        # All checks passed - create session
        return await self._create_session(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=data.device_name,
            device_fingerprint=device_fingerprint,
        )

    async def complete_mfa_login(
        self,
        challenge_token: str,
        method: MFAMethod,
        code: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TokenResponse:
        """Complete login after MFA verification."""
        challenge = await self.redis.get_mfa_challenge(challenge_token)
        if not challenge:
            raise AuthError("Invalid or expired MFA challenge", "INVALID_MFA_CHALLENGE", 401)

        user_id = UUID(challenge["user_id"])
        result = await self.db.execute(
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.mfa_configs))
        )
        user = result.scalar_one_or_none()
        if not user:
            raise UserNotFoundError()

        # Find active MFA config for this method
        mfa_config = next(
            (m for m in user.mfa_configs if m.method == method and m.is_active),
            None,
        )
        if not mfa_config:
            raise AuthError("MFA method not configured", "INVALID_MFA_METHOD", 400)

        # Verify the code
        verified = False
        if method == MFAMethod.TOTP:
            verified = verify_totp(mfa_config.totp_secret, code)
        elif method == MFAMethod.SMS_OTP:
            otp_data = await self.redis.get_otp(user.phone_number, "login_otp")
            if otp_data and _hash_token(code) == otp_data.get("code_hash"):
                verified = True
                await self.redis.delete_otp(user.phone_number, "login_otp")

        if not verified:
            await self._audit(
                user_id=user.id,
                action=AuditAction.MFA_FAILED,
                success=False,
                ip_address=ip_address,
                failure_reason=f"invalid_{method.value}_code",
            )
            raise AuthError("Invalid MFA code", "INVALID_MFA_CODE", 401)

        # Update last used
        mfa_config.last_used_at = datetime.now(UTC)
        await self.redis.complete_mfa_challenge(challenge_token)

        await self._audit(
            user_id=user.id,
            action=AuditAction.MFA_VERIFIED,
            success=True,
            ip_address=ip_address,
            metadata={"method": method.value},
        )

        return await self._create_session(user, ip_address=ip_address, user_agent=user_agent)

    # ─── Token Management ─────────────────────────────────────────────────────

    async def refresh_tokens(
        self,
        refresh_token: str,
        ip_address: str | None = None,
    ) -> TokenResponse:
        """Exchange a valid refresh token for new access + refresh tokens (rotation)."""
        from jose import JWTError

        try:
            from app.core.security import decode_token
            payload = decode_token(refresh_token)
        except JWTError:
            raise AuthError("Invalid refresh token", "INVALID_REFRESH_TOKEN", 401)

        if payload.get("type") != "refresh":
            raise AuthError("Invalid token type", "INVALID_TOKEN_TYPE", 401)

        # Check blacklist
        jti = payload.get("jti", "")
        if await self.redis.is_token_blacklisted(jti):
            raise AuthError("Token has been revoked", "TOKEN_REVOKED", 401)

        # Load user
        user_id = UUID(payload["sub"])
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise AuthError("User not found or inactive", "USER_INACTIVE", 401)

        # Blacklist the old refresh token
        token_hash = _hash_token(refresh_token)
        exp = payload.get("exp", 0)
        remaining_ttl = max(0, int(exp - datetime.now(UTC).timestamp()))
        await self.redis.blacklist_token(jti, remaining_ttl)

        await self._audit(
            user_id=user.id,
            action=AuditAction.TOKEN_REFRESHED,
            success=True,
            ip_address=ip_address,
        )

        return await self._create_session(user, ip_address=ip_address)

    async def logout(
        self,
        user: User,
        refresh_token: str | None = None,
        all_devices: bool = False,
        ip_address: str | None = None,
    ) -> None:
        """Logout: blacklist tokens and deactivate sessions."""
        if all_devices:
            # Deactivate all sessions in DB
            await self.db.execute(
                update(UserSession)
                .where(UserSession.user_id == user.id, UserSession.is_active.is_(True))
                .values(is_active=False)
            )
            await self.redis.remove_all_sessions(str(user.id))
        elif refresh_token:
            try:
                from app.core.security import decode_token
                payload = decode_token(refresh_token)
                jti = payload.get("jti", "")
                exp = payload.get("exp", 0)
                remaining_ttl = max(0, int(exp - datetime.now(UTC).timestamp()))
                await self.redis.blacklist_token(jti, remaining_ttl)

                # Deactivate specific session
                token_hash = _hash_token(refresh_token)
                await self.db.execute(
                    update(UserSession)
                    .where(UserSession.refresh_token_hash == token_hash)
                    .values(is_active=False)
                )
            except Exception:
                pass  # Best-effort logout

        await self._audit(
            user_id=user.id,
            action=AuditAction.LOGOUT,
            success=True,
            ip_address=ip_address,
            metadata={"all_devices": all_devices},
        )
        logger.info("user_logged_out", user_id=str(user.id), all_devices=all_devices)

    # ─── OTP / Phone Verification ─────────────────────────────────────────────

    async def send_otp(self, phone: str, purpose: str) -> str:
        """
        Generate OTP, store hash in Redis, return plaintext for SMS dispatch.
        Never log the actual OTP code.
        """
        otp = generate_otp(6)
        code_hash = _hash_token(otp)

        await self.redis.store_otp(
            phone=phone,
            code_hash=code_hash,
            purpose=purpose,
            ttl_seconds=settings.MFA_TOKEN_EXPIRE_SECONDS,
        )

        logger.info("otp_sent", phone=phone[-4:], purpose=purpose)  # Log last 4 digits only
        return otp

    async def verify_otp(self, phone: str, code: str, purpose: str) -> bool:
        """Verify an OTP code and mark phone as verified if valid."""
        otp_data = await self.redis.get_otp(phone, purpose)
        if not otp_data:
            raise InvalidOTPError()

        attempts = await self.redis.increment_otp_attempts(phone, purpose)
        if attempts > 3:
            await self.redis.delete_otp(phone, purpose)
            raise AuthError("Too many OTP attempts", "OTP_EXHAUSTED", 429)

        if not secrets.compare_digest(_hash_token(code), otp_data["code_hash"]):
            raise InvalidOTPError()

        # Valid - clean up
        await self.redis.delete_otp(phone, purpose)

        if purpose == "phone_verify":
            await self.db.execute(
                update(User)
                .where(User.phone_number == phone)
                .values(phone_verified=True, status=UserStatus.ACTIVE)
            )
            logger.info("phone_verified", phone=phone[-4:])

        return True

    # ─── MFA Setup ────────────────────────────────────────────────────────────

    async def setup_totp(self, user: User) -> dict:
        """Initialize TOTP setup. Returns secret + provisioning URI."""
        secret = generate_totp_secret()
        uri = get_totp_provisioning_uri(secret, user.phone_number)
        backup_codes = generate_backup_codes(10)

        # Store pending TOTP config (not yet active - needs verification)
        existing = await self.db.execute(
            select(MFAConfig).where(
                MFAConfig.user_id == user.id,
                MFAConfig.method == MFAMethod.TOTP,
            )
        )
        mfa = existing.scalar_one_or_none()

        if not mfa:
            mfa = MFAConfig(
                user_id=user.id,
                method=MFAMethod.TOTP,
                is_active=False,
            )
            self.db.add(mfa)

        mfa.totp_secret = secret  # TODO: encrypt with KMS in production
        mfa.backup_codes_hashed = [hash_backup_code(c) for c in backup_codes]

        return {
            "secret": secret,
            "provisioning_uri": uri,
            "backup_codes": backup_codes,
        }

    async def confirm_totp_setup(self, user: User, totp_code: str) -> None:
        """Activate TOTP after user confirms first code."""
        result = await self.db.execute(
            select(MFAConfig).where(
                MFAConfig.user_id == user.id,
                MFAConfig.method == MFAMethod.TOTP,
            )
        )
        mfa = result.scalar_one_or_none()
        if not mfa or not mfa.totp_secret:
            raise AuthError("TOTP setup not initiated", "TOTP_NOT_INITIATED", 400)

        if not verify_totp(mfa.totp_secret, totp_code):
            raise AuthError("Invalid TOTP code", "INVALID_TOTP", 401)

        mfa.is_active = True
        mfa.verified_at = datetime.now(UTC)

        await self._audit(
            user_id=user.id,
            action=AuditAction.MFA_ENABLED,
            success=True,
            metadata={"method": MFAMethod.TOTP.value},
        )

    # ─── Password Management ──────────────────────────────────────────────────

    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
        ip_address: str | None = None,
    ) -> None:
        """Change password for authenticated user."""
        if not verify_password(current_password, user.hashed_password):
            raise AuthError("Current password is incorrect", "WRONG_PASSWORD", 401)

        is_valid, errors = validate_password_strength(new_password)
        if not is_valid:
            raise WeakPasswordError(errors)

        user.hashed_password = get_password_hash(new_password)
        user.password_changed_at = datetime.now(UTC)

        await self._audit(
            user_id=user.id,
            action=AuditAction.PASSWORD_CHANGED,
            success=True,
            ip_address=ip_address,
        )

    # ─── Internal Helpers ─────────────────────────────────────────────────────

    async def _create_session(
        self,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_name: str | None = None,
        device_fingerprint: str | None = None,
    ) -> TokenResponse:
        """Create access + refresh tokens and persist session."""
        extra_claims = {
            "role": user.role.value,
            "phone": user.phone_number,
            "lang": user.preferred_language,
            "region": user.region,
        }

        access_token = create_access_token(user.id, extra_claims=extra_claims)
        refresh_token = create_refresh_token(user.id, extra_claims={"role": user.role.value})

        # Persist session
        session = UserSession(
            user_id=user.id,
            refresh_token_hash=_hash_token(refresh_token),
            device_name=device_name,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
            ip_address=ip_address,
            is_active=True,
            mfa_verified=True,
            expires_at=datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        self.db.add(session)

        # Update user's last login
        user.last_login_at = datetime.now(UTC)
        user.last_login_ip = ip_address
        user.failed_login_attempts = 0
        user.locked_until = None

        await self.db.flush()

        # Register in Redis
        await self.redis.reset_failed_logins(user.phone_number)
        await self.redis.register_session(str(user.id), str(session.id))

        await self._audit(
            user_id=user.id,
            action=AuditAction.LOGIN_SUCCESS,
            success=True,
            ip_address=ip_address,
            session_id=session.id,
        )

        logger.info(
            "user_logged_in",
            user_id=str(user.id),
            role=user.role.value,
            ip=ip_address,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserPublicProfile.model_validate(user),
        )

    async def _create_mfa_challenge(
        self,
        user: User,
        active_mfa: list[MFAConfig],
    ) -> dict:
        """Create a temporary MFA challenge token after password verification."""
        challenge_token = secrets.token_urlsafe(32)
        methods = [m.method for m in active_mfa]

        await self.redis.store_mfa_challenge(
            challenge_token=challenge_token,
            user_id=str(user.id),
            methods=[m.value for m in methods],
            ttl_seconds=300,
        )

        return {
            "mfa_required": True,
            "mfa_methods": methods,
            "challenge_token": challenge_token,
            "message": "MFA verification required",
        }

    async def _handle_failed_login(
        self,
        user: User,
        ip_address: str | None,
    ) -> None:
        """Increment failed attempts and lock account if threshold exceeded."""
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= settings.PASSWORD_MAX_ATTEMPTS:
            user.status = UserStatus.LOCKED
            user.locked_until = datetime.now(UTC) + timedelta(
                minutes=settings.ACCOUNT_LOCKOUT_MINUTES
            )
            await self._audit(
                user_id=user.id,
                action=AuditAction.ACCOUNT_LOCKED,
                success=True,
                ip_address=ip_address,
                metadata={"attempts": user.failed_login_attempts},
            )
            logger.warning(
                "account_locked",
                user_id=str(user.id),
                locked_until=user.locked_until.isoformat(),
            )

        await self._audit(
            user_id=user.id,
            action=AuditAction.LOGIN_FAILED,
            success=False,
            ip_address=ip_address,
            failure_reason="wrong_password",
            metadata={"attempts": user.failed_login_attempts},
        )

    async def _audit(
        self,
        action: AuditAction,
        success: bool,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None,
        failure_reason: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Persist an audit log entry."""
        log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            success=success,
            failure_reason=failure_reason,
            metadata_=metadata or {},
        )
        self.db.add(log)
