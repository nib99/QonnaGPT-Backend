"""
QonnaGPT Auth Service - Redis Client
Handles: token blacklisting, OTP storage, session caching, rate limit state.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import structlog
from redis.asyncio import ConnectionPool, Redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError, TimeoutError

from app.core.config import settings

logger = structlog.get_logger(__name__)

# ─── Key Prefixes ─────────────────────────────────────────────────────────────
KEY_OTP = "auth:otp:{purpose}:{phone}"
KEY_BLACKLIST = "auth:blacklist:{jti}"
KEY_MFA_CHALLENGE = "auth:mfa_challenge:{token}"
KEY_LOGIN_ATTEMPTS = "auth:login_attempts:{phone}"
KEY_REFRESH_SESSION = "auth:session:{token_hash}"
KEY_USER_SESSIONS = "auth:user_sessions:{user_id}"
KEY_RATE_LIMIT = "auth:rate:{endpoint}:{identifier}"


def create_redis_pool() -> ConnectionPool:
    """Create a connection pool with retry logic."""
    retry = Retry(ExponentialBackoff(cap=10, base=1), retries=3)
    return ConnectionPool.from_url(
        settings.REDIS_URL,
        max_connections=settings.REDIS_MAX_CONNECTIONS,
        decode_responses=True,
        retry=retry,
        retry_on_error=[ConnectionError, TimeoutError],
        socket_connect_timeout=5,
        socket_timeout=5,
        health_check_interval=30,
    )


_pool: ConnectionPool | None = None


def get_redis_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = create_redis_pool()
    return _pool


async def get_redis() -> Redis:
    """FastAPI dependency: get Redis client."""
    return Redis(connection_pool=get_redis_pool())


class AuthRedisService:
    """
    High-level Redis operations for the auth service.
    Encapsulates key patterns and TTL management.
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    # ─── OTP Management ───────────────────────────────────────────────────────

    async def store_otp(
        self,
        phone: str,
        code_hash: str,
        purpose: str,
        ttl_seconds: int = 300,
    ) -> None:
        """Store OTP hash with expiry. One OTP per phone+purpose."""
        key = KEY_OTP.format(purpose=purpose, phone=phone)
        await self.redis.setex(
            key,
            ttl_seconds,
            json.dumps({"code_hash": code_hash, "attempts": 0}),
        )

    async def get_otp(self, phone: str, purpose: str) -> dict | None:
        """Retrieve OTP data."""
        key = KEY_OTP.format(purpose=purpose, phone=phone)
        data = await self.redis.get(key)
        return json.loads(data) if data else None

    async def increment_otp_attempts(self, phone: str, purpose: str) -> int:
        """Increment and return attempt count."""
        key = KEY_OTP.format(purpose=purpose, phone=phone)
        data = await self.redis.get(key)
        if not data:
            return 0
        parsed = json.loads(data)
        parsed["attempts"] += 1
        ttl = await self.redis.ttl(key)
        if ttl > 0:
            await self.redis.setex(key, ttl, json.dumps(parsed))
        return parsed["attempts"]

    async def delete_otp(self, phone: str, purpose: str) -> None:
        """Invalidate OTP after use."""
        key = KEY_OTP.format(purpose=purpose, phone=phone)
        await self.redis.delete(key)

    # ─── Token Blacklisting ───────────────────────────────────────────────────

    async def blacklist_token(self, jti: str, expires_in_seconds: int) -> None:
        """Add JWT ID to blacklist until expiry."""
        key = KEY_BLACKLIST.format(jti=jti)
        await self.redis.setex(key, expires_in_seconds, "1")

    async def is_token_blacklisted(self, jti: str) -> bool:
        """Check if a JWT has been revoked."""
        key = KEY_BLACKLIST.format(jti=jti)
        return bool(await self.redis.exists(key))

    # ─── MFA Challenge ────────────────────────────────────────────────────────

    async def store_mfa_challenge(
        self,
        challenge_token: str,
        user_id: str,
        methods: list[str],
        ttl_seconds: int = 300,
    ) -> None:
        """Store pending MFA challenge after initial password auth."""
        key = KEY_MFA_CHALLENGE.format(token=challenge_token)
        await self.redis.setex(
            key,
            ttl_seconds,
            json.dumps({"user_id": user_id, "methods": methods, "verified": False}),
        )

    async def get_mfa_challenge(self, challenge_token: str) -> dict | None:
        """Retrieve MFA challenge state."""
        key = KEY_MFA_CHALLENGE.format(token=challenge_token)
        data = await self.redis.get(key)
        return json.loads(data) if data else None

    async def complete_mfa_challenge(self, challenge_token: str) -> None:
        """Mark MFA challenge as completed and delete."""
        key = KEY_MFA_CHALLENGE.format(token=challenge_token)
        await self.redis.delete(key)

    # ─── Login Attempt Tracking ───────────────────────────────────────────────

    async def increment_failed_login(
        self,
        phone: str,
        window_seconds: int = 3600,
    ) -> int:
        """Track failed login attempts for lockout policy."""
        key = KEY_LOGIN_ATTEMPTS.format(phone=phone)
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, window_seconds)
        return count

    async def get_failed_login_count(self, phone: str) -> int:
        key = KEY_LOGIN_ATTEMPTS.format(phone=phone)
        value = await self.redis.get(key)
        return int(value) if value else 0

    async def reset_failed_logins(self, phone: str) -> None:
        """Clear failed attempt counter on successful login."""
        key = KEY_LOGIN_ATTEMPTS.format(phone=phone)
        await self.redis.delete(key)

    # ─── Session Registry ─────────────────────────────────────────────────────

    async def register_session(
        self,
        user_id: str,
        session_id: str,
        ttl_days: int = 30,
    ) -> None:
        """Track active sessions per user for multi-device management."""
        key = KEY_USER_SESSIONS.format(user_id=user_id)
        await self.redis.sadd(key, session_id)
        await self.redis.expire(key, ttl_days * 86400)

    async def get_user_sessions(self, user_id: str) -> set[str]:
        """Get all active session IDs for a user."""
        key = KEY_USER_SESSIONS.format(user_id=user_id)
        return await self.redis.smembers(key)

    async def remove_session(self, user_id: str, session_id: str) -> None:
        key = KEY_USER_SESSIONS.format(user_id=user_id)
        await self.redis.srem(key, session_id)

    async def remove_all_sessions(self, user_id: str) -> None:
        """Remove all session registry entries (force logout all devices)."""
        key = KEY_USER_SESSIONS.format(user_id=user_id)
        await self.redis.delete(key)

    # ─── Health Check ─────────────────────────────────────────────────────────

    async def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            return await self.redis.ping()
        except Exception:
            return False
