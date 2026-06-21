"""
QonnaGPT Auth Service - Authentication Endpoints
POST /auth/register
POST /auth/login
POST /auth/mfa/verify
POST /auth/otp/send
POST /auth/otp/verify
POST /auth/refresh
POST /auth/logout
POST /auth/password/change
POST /auth/password/reset/request
POST /auth/password/reset/confirm
POST /auth/mfa/totp/setup
POST /auth/mfa/totp/confirm
DELETE /auth/mfa/{method}
GET  /auth/sessions
DELETE /auth/sessions/{session_id}
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    DBSession,
    RedisServiceDep,
    get_client_ip,
    require_verified_phone,
)
from app.models.auth import MFAMethod, UserRole
from app.schemas.auth import (
    AdminUpdateUserRequest,
    DisableMFARequest,
    EnableTOTPResponse,
    LoginRequest,
    LogoutRequest,
    MFAChallengeRequired,
    MFAVerifyRequest,
    MessageResponse,
    PasswordChangeRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    SendOTPRequest,
    TokenResponse,
    UserDetailProfile,
    UserRegisterRequest,
    UserRegisterResponse,
    VerifyOTPRequest,
    VerifyTOTPSetupRequest,
)
from app.services.auth_service import (
    AccountLockedError,
    AuthError,
    AuthService,
    DuplicatePhoneError,
    InvalidCredentialsError,
    InvalidOTPError,
    MFARequiredError,
    PhoneNotVerifiedError,
    UserNotFoundError,
    WeakPasswordError,
)
from app.utils.notification import dispatch_otp_sms

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address)


def get_auth_service(db: DBSession, redis: RedisServiceDep) -> AuthService:
    return AuthService(db, redis)


def _handle_auth_error(exc: AuthError) -> JSONResponse:
    """Convert AuthError to appropriate HTTP response."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc), "code": exc.code},
    )


# ─── Registration ─────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=UserRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user (farmer, extension worker, etc.)",
    description="Creates user account and sends OTP for phone verification.",
)
@limiter.limit("3/minute")
async def register(
    request: Request,
    data: UserRegisterRequest,
    background_tasks: BackgroundTasks,
    auth_svc: AuthService = Depends(get_auth_service),
) -> UserRegisterResponse:
    try:
        user = await auth_svc.register(
            data=data,
            ip_address=get_client_ip(request),
        )

        # Send OTP in background (don't block response)
        otp = await auth_svc.send_otp(data.phone_number, "phone_verify")
        background_tasks.add_task(dispatch_otp_sms, data.phone_number, otp, "phone_verify")

        logger.info("registration_completed", user_id=str(user.id))
        return UserRegisterResponse.model_validate(user)

    except DuplicatePhoneError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except WeakPasswordError as e:
        raise HTTPException(status_code=400, detail={"message": str(e), "errors": e.errors})


# ─── Login ────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    summary="Authenticate user with phone + password",
    description="Returns JWT tokens on success, or MFA challenge if enabled.",
)
@limiter.limit("5/minute")
async def login(
    request: Request,
    data: LoginRequest,
    auth_svc: AuthService = Depends(get_auth_service),
):
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")
    device_fp = request.headers.get("X-Device-Fingerprint")

    try:
        result = await auth_svc.login(
            data=data,
            ip_address=ip,
            user_agent=user_agent,
            device_fingerprint=device_fp,
        )

        # MFA required path
        if isinstance(result, dict) and result.get("mfa_required"):
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content=result,
            )

        return result  # TokenResponse

    except AccountLockedError as e:
        raise HTTPException(
            status_code=423,
            detail={"message": str(e), "locked_until": e.locked_until.isoformat()},
        )
    except PhoneNotVerifiedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


# ─── MFA ──────────────────────────────────────────────────────────────────────

@router.post(
    "/mfa/verify",
    response_model=TokenResponse,
    summary="Complete MFA challenge after password authentication",
)
@limiter.limit("5/minute")
async def verify_mfa(
    request: Request,
    data: MFAVerifyRequest,
    auth_svc: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        return await auth_svc.complete_mfa_login(
            challenge_token=data.challenge_token,
            method=data.method,
            code=data.code,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


# ─── OTP ──────────────────────────────────────────────────────────────────────

@router.post(
    "/otp/send",
    response_model=MessageResponse,
    summary="Send OTP to phone number (verification or password reset)",
)
@limiter.limit("3/minute")
async def send_otp(
    request: Request,
    data: SendOTPRequest,
    background_tasks: BackgroundTasks,
    auth_svc: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        otp = await auth_svc.send_otp(data.phone_number, data.purpose)
        background_tasks.add_task(dispatch_otp_sms, data.phone_number, otp, data.purpose)
        return MessageResponse(message="OTP sent successfully. Valid for 5 minutes.")
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


@router.post(
    "/otp/verify",
    response_model=MessageResponse,
    summary="Verify OTP code",
)
@limiter.limit("5/minute")
async def verify_otp(
    request: Request,
    data: VerifyOTPRequest,
    auth_svc: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_svc.verify_otp(data.phone_number, data.code, data.purpose)
        return MessageResponse(message="OTP verified successfully.")
    except (InvalidOTPError, AuthError) as e:
        raise HTTPException(
            status_code=e.status_code if hasattr(e, "status_code") else 401,
            detail=str(e),
        )


# ─── Token Management ─────────────────────────────────────────────────────────

@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token using refresh token (rotation)",
)
async def refresh_token(
    request: Request,
    data: RefreshTokenRequest,
    auth_svc: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        return await auth_svc.refresh_tokens(
            refresh_token=data.refresh_token,
            ip_address=get_client_ip(request),
        )
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout - invalidate token(s)",
)
async def logout(
    request: Request,
    data: LogoutRequest,
    current_user: CurrentUser,
    auth_svc: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    await auth_svc.logout(
        user=current_user,
        refresh_token=data.refresh_token,
        all_devices=data.all_devices,
        ip_address=get_client_ip(request),
    )
    msg = "Logged out from all devices" if data.all_devices else "Logged out successfully"
    return MessageResponse(message=msg)


# ─── Profile ──────────────────────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserDetailProfile,
    summary="Get current user profile",
)
async def get_me(current_user: CurrentUser) -> UserDetailProfile:
    return UserDetailProfile.model_validate(current_user)


# ─── Password Management ──────────────────────────────────────────────────────

@router.post(
    "/password/change",
    response_model=MessageResponse,
    summary="Change password for authenticated user",
    dependencies=[Depends(require_verified_phone())],
)
async def change_password(
    request: Request,
    data: PasswordChangeRequest,
    current_user: CurrentUser,
    auth_svc: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_svc.change_password(
            user=current_user,
            current_password=data.current_password,
            new_password=data.new_password,
            ip_address=get_client_ip(request),
        )
        return MessageResponse(message="Password changed successfully")
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


@router.post(
    "/password/reset/request",
    response_model=MessageResponse,
    summary="Request password reset OTP",
)
@limiter.limit("3/minute")
async def request_password_reset(
    request: Request,
    data: SendOTPRequest,
    background_tasks: BackgroundTasks,
    auth_svc: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    # Always return success to prevent user enumeration
    try:
        otp = await auth_svc.send_otp(data.phone_number, "password_reset")
        background_tasks.add_task(dispatch_otp_sms, data.phone_number, otp, "password_reset")
    except Exception:
        pass  # Silent failure

    return MessageResponse(
        message="If an account exists with this number, a reset code has been sent."
    )


@router.post(
    "/password/reset/confirm",
    response_model=MessageResponse,
    summary="Confirm password reset with OTP",
)
@limiter.limit("5/minute")
async def confirm_password_reset(
    request: Request,
    data: PasswordResetRequest,
    db: DBSession,
    redis: RedisServiceDep,
) -> MessageResponse:
    from sqlalchemy import select, update
    from app.core.security import get_password_hash
    from app.models.auth import User
    import hashlib, secrets

    auth_svc = AuthService(db, redis)

    try:
        await auth_svc.verify_otp(data.phone_number, data.otp_code, "password_reset")
    except (InvalidOTPError, AuthError) as e:
        raise HTTPException(status_code=401, detail="Invalid or expired reset code")

    from app.core.security import validate_password_strength
    is_valid, errors = validate_password_strength(data.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=errors)

    from datetime import UTC, datetime
    await db.execute(
        update(User)
        .where(User.phone_number == data.phone_number)
        .values(
            hashed_password=get_password_hash(data.new_password),
            password_changed_at=datetime.now(UTC),
            failed_login_attempts=0,
            locked_until=None,
        )
    )

    return MessageResponse(message="Password reset successfully. Please log in.")


# ─── MFA Setup ────────────────────────────────────────────────────────────────

@router.post(
    "/mfa/totp/setup",
    response_model=EnableTOTPResponse,
    summary="Initialize TOTP authenticator app setup",
    dependencies=[Depends(require_verified_phone())],
)
async def setup_totp(
    current_user: CurrentUser,
    auth_svc: AuthService = Depends(get_auth_service),
) -> EnableTOTPResponse:
    result = await auth_svc.setup_totp(current_user)
    return EnableTOTPResponse(**result)


@router.post(
    "/mfa/totp/confirm",
    response_model=MessageResponse,
    summary="Activate TOTP by confirming first code from authenticator app",
)
async def confirm_totp(
    data: VerifyTOTPSetupRequest,
    current_user: CurrentUser,
    auth_svc: AuthService = Depends(get_auth_service),
) -> MessageResponse:
    try:
        await auth_svc.confirm_totp_setup(current_user, data.totp_code)
        return MessageResponse(message="TOTP authenticator enabled successfully")
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
