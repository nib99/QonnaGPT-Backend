"""
QonnaGPT Auth Service - Configuration
Production-grade settings management using Pydantic Settings v2.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import AnyHttpUrl, AnyUrl, BeforeValidator, Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_cors(v: Any) -> list[str] | str:
    if isinstance(v, str) and not v.startswith("["):
        return [i.strip() for i in v.split(",")]
    elif isinstance(v, list | str):
        return v
    raise ValueError(v)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        case_sensitive=False,
    )

    # ─── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "QonnaGPT Auth Service"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False
    SERVICE_PORT: int = 8001
    API_V1_PREFIX: str = "/api/v1"
    WORKERS: int = 4

    # ─── Security ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALGORITHM: str = "RS256"
    # RSA keys - load from file or env in production
    JWT_PRIVATE_KEY: str = ""
    JWT_PUBLIC_KEY: str = ""
    # Fallback to HS256 secret for dev
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    MFA_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes

    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 30

    # ─── Database ─────────────────────────────────────────────────────────────
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "qonnagpt"
    POSTGRES_PASSWORD: str = "changeme_in_production"
    POSTGRES_DB: str = "qonnagpt_auth"

    # Connection pool
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ─── Redis ────────────────────────────────────────────────────────────────
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0
    REDIS_MAX_CONNECTIONS: int = 100

    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # ─── SMS / MFA ────────────────────────────────────────────────────────────
    SMS_PROVIDER: Literal["ethio_telecom", "africa_talking", "twilio"] = "ethio_telecom"
    SMS_API_KEY: str = ""
    SMS_API_SECRET: str = ""
    SMS_SENDER_ID: str = "QONNAGPT"
    TOTP_ISSUER: str = "QonnaGPT"

    # ─── CORS ─────────────────────────────────────────────────────────────────
    BACKEND_CORS_ORIGINS: Annotated[list[AnyHttpUrl] | str, BeforeValidator(parse_cors)] = []

    # ─── Rate Limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"
    RATE_LIMIT_OTP: str = "3/minute"
    RATE_LIMIT_DEFAULT: str = "100/minute"

    # ─── Observability ────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: Literal["json", "console"] = "json"
    OTEL_ENDPOINT: str = "http://otel-collector:4317"
    OTEL_SERVICE_NAME: str = "auth-service"
    ENABLE_METRICS: bool = True
    METRICS_PATH: str = "/metrics"

    # ─── External Services ────────────────────────────────────────────────────
    USER_SERVICE_URL: str = "http://user-service:8002"
    NOTIFICATION_SERVICE_URL: str = "http://notification-service:8010"

    # ─── Admin ────────────────────────────────────────────────────────────────
    FIRST_SUPERUSER_PHONE: str = "+251911000000"
    FIRST_SUPERUSER_PASSWORD: str = "changeme_in_production"

    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        return v.lower()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings instance - singleton pattern."""
    return Settings()


settings = get_settings()
