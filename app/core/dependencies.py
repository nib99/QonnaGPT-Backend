"""
QonnaGPT Auth Service - FastAPI Dependencies
JWT validation, RBAC enforcement, service injection.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import decode_token
from app.db.session import get_db
from app.models.auth import User, UserRole, UserStatus
from app.utils.redis_client import AuthRedisService, get_redis

logger = structlog.get_logger(__name__)

security = HTTPBearer(auto_error=True)

# ─── Database & Redis Dependencies ────────────────────────────────────────────

DBSession = Annotated[AsyncSession, Depends(get_db)]


async def get_redis_dep() -> Redis:
    return await get_redis()


RedisDep = Annotated[Redis, Depends(get_redis_dep)]


async def get_redis_service(redis: RedisDep) -> AuthRedisService:
    return AuthRedisService(redis)


RedisServiceDep = Annotated[AuthRedisService, Depends(get_redis_service)]

# ─── JWT Extraction ───────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str | None:
    """Extract real IP, respecting X-Forwarded-For from load balancer."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: DBSession,
    redis_service: RedisServiceDep,
) -> User:
    """
    Extract and validate current user from Bearer JWT token.
    Checks: signature, expiry, blacklist, user active status.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(credentials.credentials)
    except JWTError as e:
        logger.warning("jwt_decode_failed", error=str(e))
        raise credentials_exception

    # Validate token type
    if payload.get("type") != "access":
        raise credentials_exception

    # Check blacklist
    jti = payload.get("jti", "")
    if jti and await redis_service.is_token_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Load user
    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise credentials_exception

    result = await db.execute(
        select(User)
        .where(User.id == user_uuid)
        .options(selectinload(User.mfa_configs))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    if user.status == UserStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended",
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


# ─── Optional Auth (for public endpoints that can show extra data if logged in) ─

async def get_optional_user(
    request: Request,
    db: DBSession,
    redis_service: RedisServiceDep,
) -> User | None:
    """Return user if authenticated, None otherwise."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ", 1)[1]
        from fastapi.security import HTTPAuthorizationCredentials
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        return await get_current_user(creds, db, redis_service)
    except Exception:
        return None


OptionalUser = Annotated[User | None, Depends(get_optional_user)]


# ─── RBAC Enforcement ─────────────────────────────────────────────────────────

def require_roles(*allowed_roles: UserRole):
    """
    Dependency factory for role-based access control.
    Usage: Depends(require_roles(UserRole.ADMIN, UserRole.SUPERADMIN))
    """
    async def role_checker(current_user: CurrentUser) -> User:
        if current_user.role not in allowed_roles and not current_user.is_superuser:
            logger.warning(
                "rbac_denied",
                user_id=str(current_user.id),
                user_role=current_user.role.value,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return role_checker


def require_verified_phone():
    """Ensure phone number is verified before allowing sensitive operations."""
    async def phone_checker(current_user: CurrentUser) -> User:
        if not current_user.phone_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Phone number verification required",
            )
        return current_user
    return phone_checker


# ─── ABAC (Attribute-Based Access) ───────────────────────────────────────────

def require_same_region_or_admin():
    """
    ABAC check: user can only access resources in their own region,
    unless they are admin/superadmin.
    """
    async def abac_checker(
        current_user: CurrentUser,
        region: str | None = None,
    ) -> User:
        admin_roles = {UserRole.ADMIN, UserRole.SUPERADMIN, UserRole.GOVERNMENT_OFFICIAL}
        if current_user.role in admin_roles or current_user.is_superuser:
            return current_user

        if region and current_user.region and region != current_user.region:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: cross-region access not permitted",
            )
        return current_user

    return abac_checker


# ─── Convenience Aliases ──────────────────────────────────────────────────────

AdminUser = Annotated[User, Depends(require_roles(UserRole.ADMIN, UserRole.SUPERADMIN))]
SuperAdmin = Annotated[User, Depends(require_roles(UserRole.SUPERADMIN))]
