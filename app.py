# /opt/soar-engine/app.py
"""
AI-SOAR Engine - FastAPI Application Entrypoint
Production-grade SOAR platform with Wazuh integration.
"""
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator
 
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
 
from config import get_settings
from logger import setup_logger, app_logger
from routes.webhook import router as webhook_router
 
settings = get_settings()
logger = setup_logger("soar.app", settings.soar_log_level)
 
 
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager: startup and shutdown logic."""
    # ── Startup ───────────────────────────────────────────────────────────────
    app_logger.info("=" * 60)
    app_logger.info("AI-SOAR Engine starting up...")
    app_logger.info(f"Environment: {settings.soar_env}")
    app_logger.info(f"AI Provider: {settings.ai_provider}")
    app_logger.info(f"Auto-block: {settings.enable_auto_block}")
    app_logger.info(f"Log level: {settings.soar_log_level}")
    app_logger.info("=" * 60)
 
    yield
 
    # ── Shutdown ──────────────────────────────────────────────────────────────
    app_logger.info("AI-SOAR Engine shutting down gracefully...")
 
 
app = FastAPI(
    title="AI-SOAR Engine",
    description="AI-powered Security Orchestration, Automation and Response platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.soar_env != "production" else None,
    redoc_url=None,
)
# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost"],  # Restrict in production
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-Wazuh-Secret"],
)
 
 
@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log all requests with timing information."""
    start = time.time()
    response = await call_next(request)
    elapsed = round((time.time() - start) * 1000, 2)
    logger.info(
        f"{request.method} {request.url.path} "
        f"-> {response.status_code} ({elapsed}ms) "
        f"[{request.client.host}]"
    )
    return response
 
 
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler - prevent stack traces leaking to clients."""
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "path": str(request.url.path)}
    )
 
 
# ── Router Registration ───────────────────────────────────────────────────────
app.include_router(webhook_router, tags=["SOAR"])

# ── Root endpoint ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    """Root endpoint - basic health/status message."""
    return {"status": "AI-SOAR Engine running"} 
 
if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=settings.soar_host,
        port=settings.soar_port,
        reload=settings.soar_env == "development",
        log_level=settings.soar_log_level.lower(),
        access_log=True,
    )
