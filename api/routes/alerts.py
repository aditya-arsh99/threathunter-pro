"""
=============================================================
 ThreatHunter Pro — Alerts Routes
 api/routes/alerts.py

 GET    /alerts              → paginated alerts
 GET    /alerts/stats        → alert counts by severity/type
 GET    /alerts/{alert_id}   → single alert detail
 PATCH  /alerts/{alert_id}/acknowledge → acknowledge alert
 DELETE /alerts/{alert_id}  → dismiss alert
=============================================================
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query, HTTPException, Path
from pydantic import BaseModel
from loguru import logger

from api.dependencies import get_es_client

router = APIRouter(prefix="/alerts", tags=["Alerts"])
IDX_ALERTS = "threat-alerts"


# ------------------------------------------------------------------
# Request Models
# ------------------------------------------------------------------
class AcknowledgeRequest(BaseModel):
    acknowledged_by: str = "analyst"
    notes:           Optional[str] = None


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@router.get("")
def get_alerts(
    page:        int  = Query(default=1,   ge=1),
    size:        int  = Query(default=20,  ge=1, le=100),
    severity:    Optional[str]  = Query(default=None),
    source_type: Optional[str]  = Query(default=None),
    status:      Optional[str]  = Query(default=None),
    min_risk:    Optional[int]  = Query(default=None, ge=0, le=100),
):
    """Get paginated threat alerts with optional filters."""
    es     = get_es_client()
    offset = (page - 1) * size
    must   = []

    if severity:
        must.append({"term": {"severity": severity.lower()}})
    if source_type:
        must.append({"term": {"source_type": source_type.lower()}})
    if status:
        must.append({"term": {"status": status.lower()}})
    if min_risk is not None:
        must.append({"range": {"risk_score": {"gte": min_risk}}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}

    try:
        resp = es.search(
            index=IDX_ALERTS,
            body={
                "query": query,
                "sort":  [
                    {"risk_score":  {"order": "desc"}},
                    {"@timestamp":  {"order": "desc"}},
                ],
                "from":  offset,
                "size":  size,
            },
        )
        hits  = resp["hits"]["hits"]
        total = resp["hits"]["total"]["value"]

        return {
            "total":  total,
            "page":   page,
            "size":   size,
            "pages":  (total + size - 1) // size,
            "alerts": [h["_source"] for h in hits],
        }

    except Exception as e:
        logger.error(f"ES query error (alerts): {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
def get_alert_stats():
    """Returns alert counts broken down by severity, type, status."""
    es = get_es_client()

    try:
        resp = es.search(
            index=IDX_ALERTS,
            body={
                "size": 0,
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "severity", "size": 10}
                    },
                    "by_source_type": {
                        "terms": {"field": "source_type", "size": 5}
                    },
                    "by_status": {
                        "terms": {"field": "status", "size": 5}
                    },
                    "by_mitre_tactic": {
                        "terms": {"field": "mitre_tactic", "size": 10}
                    },
                    "top_src_ips": {
                        "terms": {"field": "src_ip", "size": 10}
                    },
                    "avg_risk_score": {
                        "avg": {"field": "risk_score"}
                    },
                    "critical_alerts": {
                        "filter": {"term": {"severity": "critical"}}
                    },
                    "open_alerts": {
                        "filter": {"term": {"status": "open"}}
                    },
                    "alerts_over_time": {
                        "date_histogram": {
                            "field":             "@timestamp",
                            "calendar_interval": "hour",
                            "min_doc_count":     1,
                        }
                    },
                },
            },
        )

        aggs  = resp["aggregations"]
        total = resp["hits"]["total"]["value"]

        return {
            "total_alerts":      total,
            "open_alerts":       aggs["open_alerts"]["doc_count"],
            "critical_alerts":   aggs["critical_alerts"]["doc_count"],
            "avg_risk_score":    round(aggs["avg_risk_score"].get("value") or 0, 1),
            "by_severity":       {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
            "by_source_type":    {b["key"]: b["doc_count"] for b in aggs["by_source_type"]["buckets"]},
            "by_status":         {b["key"]: b["doc_count"] for b in aggs["by_status"]["buckets"]},
            "by_mitre_tactic":   {b["key"]: b["doc_count"] for b in aggs["by_mitre_tactic"]["buckets"]},
            "top_src_ips":       [{"ip": b["key"], "count": b["doc_count"]} for b in aggs["top_src_ips"]["buckets"]],
            "alerts_over_time":  [
                {"timestamp": b["key_as_string"], "count": b["doc_count"]}
                for b in aggs["alerts_over_time"]["buckets"]
            ],
        }

    except Exception as e:
        logger.error(f"Alert stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{alert_id}")
def get_alert(alert_id: str = Path(..., description="Alert ID")):
    """Get a single alert by ID."""
    es = get_es_client()
    try:
        resp = es.get(index=IDX_ALERTS, id=alert_id)
        return resp["_source"]
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")


@router.patch("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str = Path(...),
    body:     AcknowledgeRequest = AcknowledgeRequest(),
):
    """Acknowledge an alert."""
    es = get_es_client()
    try:
        es.update(
            index=IDX_ALERTS,
            id=alert_id,
            body={
                "doc": {
                    "status":          "acknowledged",
                    "acknowledged_by": body.acknowledged_by,
                    "acknowledged_at": datetime.now(timezone.utc).isoformat(),
                    "analyst_notes":   body.notes,
                }
            },
        )
        return {"success": True, "alert_id": alert_id, "status": "acknowledged"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{alert_id}")
def dismiss_alert(alert_id: str = Path(...)):
    """Dismiss (close) an alert."""
    es = get_es_client()
    try:
        es.update(
            index=IDX_ALERTS,
            id=alert_id,
            body={
                "doc": {
                    "status":     "dismissed",
                    "closed_at":  datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        return {"success": True, "alert_id": alert_id, "status": "dismissed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
