"""
=============================================================
 ThreatHunter Pro — FastAPI Application
 api/main.py

 Endpoints:
   GET  /health                         → service health
   GET  /events/network                 → network flow events
   GET  /events/windows                 → windows events
   GET  /events/stats                   → event statistics
   GET  /alerts                         → threat alerts
   GET  /alerts/stats                   → alert statistics
   GET  /alerts/{id}                    → single alert
   PATCH /alerts/{id}/acknowledge       → acknowledge alert
   DELETE /alerts/{id}                  → dismiss alert

 Usage:
   python main.py
   uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
=============================================================
"""

import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

# Make sure imports work whether run as module or script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.routes import health, events, alerts


# ------------------------------------------------------------------
# App lifecycle
# ------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ThreatHunter Pro API starting up...")
    yield
    logger.info("ThreatHunter Pro API shutting down...")


# ------------------------------------------------------------------
# App
# ------------------------------------------------------------------
app = FastAPI(
    title       = "ThreatHunter Pro API",
    description = "Real-time threat detection platform — ML-powered anomaly detection",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

# CORS — allow React dashboard on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ------------------------------------------------------------------
# Routers
# ------------------------------------------------------------------
app.include_router(health.router)
app.include_router(events.router)
app.include_router(alerts.router)


# ------------------------------------------------------------------
# Root
# ------------------------------------------------------------------
@app.get("/", tags=["Root"])
def root():
    return {
        "name":    "ThreatHunter Pro",
        "version": "1.0.0",
        "status":  "running",
        "docs":    "http://localhost:8000/docs",
    }


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    os.makedirs("logs", exist_ok=True)
    logger.add("logs/api_{time}.log", rotation="50MB", level="INFO")
    uvicorn.run(
        "api.main:app",
        host     = "0.0.0.0",
        port     = 8000,
        reload   = True,
        log_level= "info",
    )
