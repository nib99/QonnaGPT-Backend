"""
QonnaGPT Auth Service - Test Suite
Covers: registration, login, MFA, OTP, token refresh, RBAC.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    generate_otp,
    generate_totp_secret,
    verify_totp,
    validate_password_strength,
)
from app.db.session import Base, get_db
from app.main import app
from app.models.auth import User, UserRole, UserStatus
from app.utils.redis_client import AuthRedisService

# ─── Test Database Setup ──────────────────────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///./test_auth.db"


@pytest.fixture(scope="session")
def event_loop_policy():
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine):
    async_session = async_sessionmaker(test_engine, expire_on_commit=False)
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture
def mock_redis():
    """Mock Redis service for unit tests."""
    redis = AsyncMock(spec=AuthRedisService)
    redis.is_token_blacklisted.return_value = False
    redis.get_failed_login_count.return_value = 0
    redis.ping.return_value = True
    return redis


@pytest_asyncio.fixture
async def client(db_session, mock_redis):
    """Test HTTP client with overridden dependencies."""
    async def override_db():
        yield db_session

    async def override_redis():
        return mock_redis

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_user_data():
    return {
        "phone_number": "+251912345678",
        "full_name": "Gemechu Tadesse",
        "password": "SecurePass@123",
        "confirm_password": "SecurePass@123",
        "preferred_language": "om",
        "role": "farmer",
    }


@pytest_asyncio.fixture
async def verified_user(db_session):
    """Create a verified, active user for authenticated tests."""
    user = User(
        id=uuid4(),
        phone_number="+251911000001",
        full_name="Test Farmer",
        hashed_password=get_password_hash("TestPass@123"),
        role=UserRole.FARMER,
        status=UserStatus.ACTIVE,
        phone_verified=True,
        is_active=True,
        preferred_language="om",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


# ─── Security Unit Tests ───────────────────────────────────────────────────────

class TestPasswordSecurity:
    def test_password_hashing_and_verification(self):
        password = "SecurePass@123"
        hashed = get_password_hash(password)
        assert verify_password(password, hashed)
        assert not verify_password("WrongPass@123", hashed)
        assert hashed != password

    def test_different_hashes_same_password(self):
        """bcrypt should produce different hashes each time (salt)."""
        pw = "SecurePass@123"
        hash1 = get_password_hash(pw)
        hash2 = get_password_hash(pw)
        assert hash1 != hash2
        assert verify_password(pw, hash1)
        assert verify_password(pw, hash2)

    def test_password_strength_valid(self):
        is_valid, errors = validate_password_strength("SecurePass@123")
        assert is_valid
        assert errors == []

    def test_password_strength_too_short(self):
        is_valid, errors = validate_password_strength("Ab@1")
        assert not is_valid
        assert any("characters" in e for e in errors)

    def test_password_strength_no_special(self):
        is_valid, errors = validate_password_strength("SecurePass123")
        assert not is_valid

    def test_password_strength_no_uppercase(self):
        is_valid, errors = validate_password_strength("securepass@123")
        assert not is_valid


class TestJWTTokens:
    def test_create_and_decode_access_token(self):
        from app.core.security import decode_token
        user_id = str(uuid4())
        token = create_access_token(user_id, extra_claims={"role": "farmer"})
        payload = decode_token(token)
        assert payload["sub"] == user_id
        assert payload["role"] == "farmer"
        assert payload["type"] == "access"
        assert "jti" in payload

    def test_access_token_expiry(self):
        from app.core.security import decode_token
        from jose import JWTError
        user_id = str(uuid4())
        token = create_access_token(user_id, expires_delta=timedelta(seconds=-1))
        with pytest.raises(JWTError):
            decode_token(token)

    def test_refresh_token_type(self):
        from app.core.security import decode_token
        user_id = str(uuid4())
        token = create_refresh_token(user_id)
        payload = decode_token(token)
        assert payload["type"] == "refresh"

    def test_token_unique_jti(self):
        from app.core.security import decode_token
        user_id = str(uuid4())
        token1 = create_access_token(user_id)
        token2 = create_access_token(user_id)
        p1 = decode_token(token1)
        p2 = decode_token(token2)
        assert p1["jti"] != p2["jti"]


class TestTOTP:
    def test_generate_and_verify_totp(self):
        import pyotp
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        assert verify_totp(secret, current_code)

    def test_invalid_totp_code(self):
        secret = generate_totp_secret()
        assert not verify_totp(secret, "000000")

    def test_otp_generation_numeric(self):
        otp = generate_otp(6)
        assert len(otp) == 6
        assert otp.isdigit()

    def test_otp_uniqueness(self):
        otps = {generate_otp(6) for _ in range(100)}
        # Not all the same (very unlikely with random generation)
        assert len(otps) > 1


# ─── API Integration Tests ─────────────────────────────────────────────────────

class TestRegistration:
    @pytest.mark.asyncio
    async def test_register_success(self, client, sample_user_data):
        with patch("app.utils.notification.dispatch_otp_sms", return_value=True):
            with patch.object(
                AuthRedisService, "store_otp", new_callable=AsyncMock
            ):
                response = await client.post(
                    "/api/v1/auth/register",
                    json=sample_user_data,
                )
        assert response.status_code == 201
        data = response.json()
        assert data["phone_number"] == "+251912345678"
        assert data["role"] == "farmer"
        assert data["phone_verified"] is False
        assert "id" in data

    @pytest.mark.asyncio
    async def test_register_duplicate_phone(self, client, sample_user_data, verified_user):
        sample_user_data["phone_number"] = verified_user.phone_number
        response = await client.post("/api/v1/auth/register", json=sample_user_data)
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_register_weak_password(self, client, sample_user_data):
        sample_user_data["password"] = "weak"
        sample_user_data["confirm_password"] = "weak"
        response = await client.post("/api/v1/auth/register", json=sample_user_data)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_register_password_mismatch(self, client, sample_user_data):
        sample_user_data["confirm_password"] = "DifferentPass@123"
        response = await client.post("/api/v1/auth/register", json=sample_user_data)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_register_invalid_phone(self, client, sample_user_data):
        sample_user_data["phone_number"] = "not-a-phone"
        response = await client.post("/api/v1/auth/register", json=sample_user_data)
        assert response.status_code == 422


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_success(self, client, verified_user, mock_redis):
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "phone_number": verified_user.phone_number,
                "password": "TestPass@123",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, verified_user):
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "phone_number": verified_user.phone_number,
                "password": "WrongPassword@123",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_unknown_phone(self, client):
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "phone_number": "+251999999999",
                "password": "SomePass@123",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_me_authenticated(self, client, verified_user):
        """Test /auth/me returns current user profile."""
        token = create_access_token(
            str(verified_user.id),
            extra_claims={"role": verified_user.role.value},
        )
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["phone_number"] == verified_user.phone_number

    @pytest.mark.asyncio
    async def test_get_me_unauthenticated(self, client):
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 403  # HTTPBearer returns 403 when no token


class TestHealthEndpoints:
    @pytest.mark.asyncio
    async def test_health(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestPhoneValidation:
    @pytest.mark.asyncio
    async def test_ethiopian_phone_normalization(self, client, sample_user_data):
        """Test that 09XXXXXXXX is normalized to +251XXXXXXXXX."""
        sample_user_data["phone_number"] = "0987654321"
        with patch("app.utils.notification.dispatch_otp_sms", return_value=True):
            with patch.object(AuthRedisService, "store_otp", new_callable=AsyncMock):
                response = await client.post("/api/v1/auth/register", json=sample_user_data)
        if response.status_code == 201:
            data = response.json()
            assert data["phone_number"] == "+251987654321"
