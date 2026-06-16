"""
=============================================================
 ThreatHunter Pro — Health Routes
 api/routes/health.py
=============================================================
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from loguru import logger

from api.dependencies import get_es_client, get_redis_client

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/")
def health_check():
    """Check health of all backend services."""
    status = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services":  {},
        "overall":   "healthy",
    }

    # Elasticsearch
    try:
        es   = get_es_client()
        info = es.cluster.health()
        status["services"]["elasticsearch"] = {
            "status":       info["status"],
            "cluster_name": info["cluster_name"],
            "nodes":        info["number_of_nodes"],
        }
    except Exception as e:
        status["services"]["elasticsearch"] = {"status": "unreachable", "error": str(e)}
        status["overall"] = "degraded"

    # Redis
    try:
        r = get_redis_client()
        r.ping()
        info = r.info("server")
        status["services"]["redis"] = {
            "status":  "ok",
            "version": info.get("redis_version", "unknown"),
        }
    except Exception as e:
        status["services"]["redis"] = {"status": "unreachable", "error": str(e)}
        status["overall"] = "degraded"

    return status
