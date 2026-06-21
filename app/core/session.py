"""
QonnaGPT Auth Service - Database Layer
Async SQLAlchemy 2.0 session management with connection pooling.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, MappedColumn
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    def to_dict(self) -> dict[str, Any]:
        """Convert model instance to dictionary."""
        return {
            col.name: getattr(self, col.name)
            for col in self.__table__.columns
        }


def create_engine() -> AsyncEngine:
    """
    Create async engine with production-ready pool settings.
    Uses NullPool for testing to avoid connection leaks.
    """
    pool_kwargs: dict[str, Any] = {}

    if settings.APP_ENV == "development" and settings.DEBUG:
        # Smaller pool for dev
        pool_kwargs = {
            "pool_size": 5,
            "max_overflow": 10,
        }
    else:
        pool_kwargs = {
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_recycle": settings.DB_POOL_RECYCLE,
            "pool_pre_ping": True,  # Verify connections before use
        }

    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        **pool_kwargs,
    )

    # Log slow queries in production
    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def receive_before_cursor_execute(conn, cursor, statement, params, context, executemany):
        context._query_start_time = __import__("time").monotonic()

    @event.listens_for(engine.sync_engine, "after_cursor_execute")
    def receive_after_cursor_execute(conn, cursor, statement, params, context, executemany):
        total = __import__("time").monotonic() - context._query_start_time
        if total > 0.5:  # Log queries slower than 500ms
            logger.warning("slow_query_detected", duration_ms=round(total * 1000), query=statement[:200])

    return engine


engine = create_engine()

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency: yield a database session per request.
    Handles commit on success, rollback on exception.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for use outside of FastAPI dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_db_health() -> dict[str, str]:
    """Health check for database connectivity."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "postgresql"}
    except Exception as e:
        logger.error("database_health_check_failed", error=str(e))
        return {"status": "unhealthy", "database": "postgresql", "error": str(e)}
