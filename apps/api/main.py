"""FastAPI Application Entrypoint for Adaptive SOC Platform."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.core.config import settings
from src.core.logging import logger
from apps.api.routes.alerts import router as alerts_router
from apps.api.routes.incidents import router as incidents_router
from apps.api.routes.investigations import router as investigations_router
from apps.api.routes.approvals import router as approvals_router
from apps.api.routes.metrics import router as metrics_router


def create_app() -> FastAPI:
    """FastAPI Application Factory."""
    app = FastAPI(
        title="Adaptive Trust-Aware SOC Multi-Agent API",
        description="Autonomous SOC alert triage with ML multi-label routing, pgvector historical memory, and deterministic Trust Gate 03.",
        version="1.0.0",
        docs_url=f"{settings.API_PREFIX}/docs",
        openapi_url=f"{settings.API_PREFIX}/openapi.json",
    )

    # Enable CORS for Frontend React integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API Routers
    api_prefix = settings.API_PREFIX
    app.include_router(alerts_router, prefix=api_prefix)
    app.include_router(incidents_router, prefix=api_prefix)
    app.include_router(investigations_router, prefix=api_prefix)
    app.include_router(approvals_router, prefix=api_prefix)
    app.include_router(metrics_router, prefix=api_prefix)

    @app.get("/health", tags=["Health"])
    async def healthcheck():
        return {
            "status": "healthy",
            "app_name": settings.APP_NAME,
            "env": settings.APP_ENV,
            "version": "1.0.0",
            "trust_gate_threshold": settings.TRUST_DEFAULT_THRESHOLD,
        }

    import os
    from fastapi.staticfiles import StaticFiles

    dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "web", "dist"))
    if os.path.exists(dist_dir):
        app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static_dashboard")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Adaptive SOC API Gateway", extra={"host": settings.HOST, "port": settings.PORT})
    uvicorn.run("apps.api.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
