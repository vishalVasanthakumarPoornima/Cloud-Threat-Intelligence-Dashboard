from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import active_scan, analyze, health, results, sources
from app.core.config import get_settings
from app.core.security import (
    AnalyzeRateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url="/redoc" if settings.app_env != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_bytes=settings.max_request_bytes,
    upload_max_bytes=settings.max_upload_file_bytes + 1_048_576,
)
app.add_middleware(AnalyzeRateLimitMiddleware, settings=settings)


@app.get("/", tags=["health"])
async def root_status():
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.app_env,
        "health": f"{settings.api_prefix}/health",
    }


app.include_router(health.router, prefix=settings.api_prefix, tags=["health"])
app.include_router(analyze.router, prefix=settings.api_prefix, tags=["analysis"])
app.include_router(active_scan.router, prefix=settings.api_prefix, tags=["active scan"])
app.include_router(results.router, prefix=settings.api_prefix, tags=["results"])
app.include_router(sources.router, prefix=settings.api_prefix, tags=["sources"])
