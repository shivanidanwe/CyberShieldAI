from pydantic import BaseModel
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.ai import router as ai_router
from app.api.alerts import router as alerts_router
from app.api.auth import ensure_demo_user, router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.packets import router as packets_router
from app.api.reports import router as reports_router
from app.database import Base, SessionLocal, engine
from app.utils.logger import get_logger

logger = get_logger("main")

Base.metadata.create_all(bind=engine)

with SessionLocal() as db:
    ensure_demo_user(db)

app = FastAPI(
    title="CyberShield AI",
    description="Mini AI-powered Security Operations Center for network monitoring and alerting.",
    version="1.0.0",
)

# Allow the Vite dev server (and any local origin) to call the API directly,
# in addition to the same-origin requests proxied by Vite.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api")
app.include_router(packets_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(ai_router, prefix="/api/ai")
app.include_router(reports_router, prefix="/api/reports")


@app.get("/")
def home():
    return {
        "message": "CyberShield AI SOC Running",
        "status": "operational",
        "features": [
            "packet collection",
            "rule-based detection",
            "AI anomaly detection",
            "AI alert explanations",
            "alert storage",
            "dashboard analytics",
            "security reports",
            "basic auth",
            "live packet capture",
        ],
    }


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "cybershield-ai",
        "version": app.version,
        "features": [
            "packet collection",
            "rule-based detection",
            "AI anomaly detection",
            "AI alert explanations",
            "alert storage",
            "dashboard analytics",
            "security reports",
            "basic auth",
            "live packet capture",
        ],
    }


class SeedRequest(BaseModel):
    force: Optional[bool] = False
    clear: Optional[bool] = False


@app.post("/api/seed")
def seed_data(payload: SeedRequest):
    """Seed demo data or clear the database."""
    from app.seed import seed as run_seed

    try:
        count = run_seed(force=payload.force, clear=payload.clear)
        action = "Cleared and re-seeded" if payload.clear else ("Force re-seeded" if payload.force else "Seeded")
        return {"message": f"{action} — {count} packets created.", "count": count}
    except Exception as exc:
        return {"message": f"Seed failed: {exc}", "count": 0}


try:
    # Seed a realistic demo dataset on first run so the dashboard is never
    # empty. Controlled by AUTO_SEED (default "1") and only runs when the
    # tables are empty. Use `python -m app.seed --clear` to reset.
    from app.seed import maybe_seed

    maybe_seed()
    logger.info("Demo-data seeding check completed.")
except Exception:  # pragma: no cover - never block startup on optional seeding
    logger.exception("Demo-data seeding check failed (continuing without seed).")