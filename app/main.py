"""
QonnaGPT Auth Service - Application Factory
Production-grade FastAPI app with full observability stack.
"""

from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.v1.endpoints.auth import router as auth_router
from app.core.config import settings
from app.db.session import check_db_health, engine
from app.utils.redis_client import get_redis_pool

# ─── Structured Logging Setup ─────────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if settings.LOG_FORMAT == "console"
        else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}.get(settings.LOG_LEVEL, 20)
    ),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger(__name__)


# ─── App Lifespan ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application startup and shutdown lifecycle.
    """
    logger.info(
        "service_starting",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
    )

    # Verify database connectivity
    db_health = await check_db_health()
    if db_health["status"] != "healthy":
        logger.error("database_startup_failed", **db_health)
        raise RuntimeError("Database not available on startup")

    # Warm up Redis connection pool
    pool = get_redis_pool()
    logger.info(
        "service_started",
        service=settings.APP_NAME,
        db=db_health["status"],
    )

    yield

    # Graceful shutdown
    logger.info("service_stopping", service=settings.APP_NAME)
    await engine.dispose()
    await pool.aclose()
    logger.info("service_stopped")


# ─── Application Factory ──────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="""
## QonnaGPT Authentication Service

Production-grade auth service for the QonnaGPT national agricultural platform.

### Features
- 📱 Phone-first authentication (Ethiopian farmers)
- 🔐 JWT tokens (RS256) with refresh token rotation
- 🔑 Multi-factor authentication (TOTP + SMS OTP + Biometric)
- 🛡️ RBAC + ABAC authorization
- 📊 Full audit logging for compliance
- 🚀 Rate limiting and account lockout
- 🌍 Multilingual OTP messages (Oromo, Amharic, English)
        """,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if settings.APP_ENV != "production" else None,
        docs_url=f"{settings.API_V1_PREFIX}/docs" if settings.APP_ENV != "production" else None,
        redoc_url=f"{settings.API_V1_PREFIX}/redoc" if settings.APP_ENV != "production" else None,
        lifespan=lifespan,
    )

    # ─── Middleware Stack ──────────────────────────────────────────────────────

    # Trusted hosts (prevent Host header injection)
    if settings.APP_ENV == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["api.qonnagpt.et", "*.qonnagpt.et"],
        )

    # CORS
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
            allow_headers=["Authorization", "Content-Type", "X-Device-Fingerprint"],
        )

    # Rate Limiting
    limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # Request ID + structured logging middleware
    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        import uuid
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.monotonic()

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None,
        )

        response = await call_next(request)

        duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        log_fn = logger.warning if response.status_code >= 400 else logger.info
        log_fn(
            "request_completed",
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms}ms"
        return response

    # Security headers middleware
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ─── Exception Handlers ───────────────────────────────────────────────────

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        errors = []
        for error in exc.errors():
            field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
            errors.append({"field": field, "message": error["msg"], "type": error["type"]})

        logger.warning("validation_error", errors=errors, path=str(request.url.path))
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Validation error", "errors": errors},
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.exception("unhandled_exception", exc_type=type(exc).__name__)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    # ─── Prometheus Metrics ───────────────────────────────────────────────────

    if settings.ENABLE_METRICS:
        instrumentator = Instrumentator(
            should_group_status_codes=True,
            should_ignore_untemplated=True,
            should_respect_env_var=True,
            should_instrument_requests_inprogress=True,
            excluded_handlers=["/health", "/metrics"],
            inprogress_name="auth_service_requests_inprogress",
            inprogress_labels=True,
        )
        instrumentator.instrument(app)
        instrumentator.expose(app, endpoint=settings.METRICS_PATH, include_in_schema=False)

    # ─── Routes ───────────────────────────────────────────────────────────────

    app.include_router(auth_router, prefix=settings.API_V1_PREFIX)

    # Health + readiness endpoints
    @app.get("/health", include_in_schema=False)
    async def health():
        return {"status": "healthy", "service": settings.APP_NAME, "version": settings.APP_VERSION}

    @app.get("/ready", include_in_schema=False)
    async def readiness():
        db_health = await check_db_health()
        is_ready = db_health["status"] == "healthy"
        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={
                "status": "ready" if is_ready else "not_ready",
                "checks": {"database": db_health["status"]},
            },
        )

    @app.get(f"{settings.API_V1_PREFIX}/openapi-spec", include_in_schema=False)
    async def get_openapi():
        """Machine-readable OpenAPI spec endpoint for API gateway."""
        return app.openapi()

    logger.info("app_created", routes=len(app.routes))
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.SERVICE_PORT,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else settings.WORKERS,
        log_config=None,  # Use structlog instead
        access_log=False,
    )
