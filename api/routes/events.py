"""
=============================================================
 ThreatHunter Pro — Events Routes
 api/routes/events.py

 GET /events/network   → paginated network flow events
 GET /events/windows   → paginated Windows events
 GET /events/stats     → counts, anomaly rates, top IPs
=============================================================
"""

from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from loguru import logger

from api.dependencies import get_es_client

router = APIRouter(prefix="/events", tags=["Events"])

IDX_NETWORK = "network-flows"
IDX_WINDOWS = "windows-events"


# ------------------------------------------------------------------
# Network Flows
# ------------------------------------------------------------------
@router.get("/network")
def get_network_events(
    page:        int  = Query(default=1,  ge=1),
    size:        int  = Query(default=20, ge=1, le=100),
    anomaly_only:bool = Query(default=False),
    severity:    Optional[str] = Query(default=None),
    src_ip:      Optional[str] = Query(default=None),
    protocol:    Optional[str] = Query(default=None),
):
    """
    Get paginated network flow events.
    Supports filtering by anomaly status, severity, IP, protocol.
    """
    es     = get_es_client()
    offset = (page - 1) * size

    must = []
    if anomaly_only:
        must.append({"term": {"is_anomaly": True}})
    if severity:
        must.append({"term": {"severity": severity.lower()}})
    if src_ip:
        must.append({"term": {"src_ip": src_ip}})
    if protocol:
        must.append({"term": {"protocol": protocol.upper()}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}

    try:
        resp = es.search(
            index=IDX_NETWORK,
            body={
                "query": query,
                "sort":  [{"@timestamp": {"order": "desc"}}],
                "from":  offset,
                "size":  size,
            },
        )
        hits  = resp["hits"]["hits"]
        total = resp["hits"]["total"]["value"]

        return {
            "total":   total,
            "page":    page,
            "size":    size,
            "pages":   (total + size - 1) // size,
            "events":  [h["_source"] for h in hits],
        }

    except Exception as e:
        logger.error(f"ES query error (network): {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------
# Windows Events
# ------------------------------------------------------------------
@router.get("/windows")
def get_windows_events(
    page:         int  = Query(default=1,  ge=1),
    size:         int  = Query(default=20, ge=1, le=100),
    anomaly_only: bool = Query(default=False),
    severity:     Optional[str] = Query(default=None),
    event_id:     Optional[int] = Query(default=None),
    computer:     Optional[str] = Query(default=None),
    user:         Optional[str] = Query(default=None),
):
    """Get paginated Windows event log entries."""
    es     = get_es_client()
    offset = (page - 1) * size

    must = []
    if anomaly_only:
        must.append({"term": {"is_anomaly": True}})
    if severity:
        must.append({"term": {"severity": severity.lower()}})
    if event_id:
        must.append({"term": {"event_id": event_id}})
    if computer:
        must.append({"term": {"computer": computer}})
    if user:
        must.append({"term": {"user": user}})

    query = {"bool": {"must": must}} if must else {"match_all": {}}

    try:
        resp = es.search(
            index=IDX_WINDOWS,
            body={
                "query": query,
                "sort":  [{"@timestamp": {"order": "desc"}}],
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
            "events": [h["_source"] for h in hits],
        }

    except Exception as e:
        logger.error(f"ES query error (windows): {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------
@router.get("/stats")
def get_event_stats():
    """
    Returns high-level statistics:
      - Total event counts
      - Anomaly rates
      - Top source IPs
      - Events per protocol
      - Top Windows Event IDs
    """
    es = get_es_client()

    try:
        # Network stats
        net_resp = es.search(
            index=IDX_NETWORK,
            body={
                "size": 0,
                "aggs": {
                    "total_anomalies": {
                        "filter": {"term": {"is_anomaly": True}}
                    },
                    "by_severity": {
                        "terms": {"field": "severity", "size": 10}
                    },
                    "by_protocol": {
                        "terms": {"field": "protocol", "size": 10}
                    },
                    "top_src_ips": {
                        "terms": {"field": "src_ip", "size": 10}
                    },
                    "top_dst_ports": {
                        "terms": {"field": "dst_port", "size": 10}
                    },
                    "avg_anomaly_score": {
                        "avg": {"field": "anomaly_score"}
                    },
                },
            },
        )

        net_aggs   = net_resp["aggregations"]
        net_total  = net_resp["hits"]["total"]["value"]

        # Windows stats
        win_resp = es.search(
            index=IDX_WINDOWS,
            body={
                "size": 0,
                "aggs": {
                    "total_anomalies": {
                        "filter": {"term": {"is_anomaly": True}}
                    },
                    "by_severity": {
                        "terms": {"field": "severity", "size": 10}
                    },
                    "top_event_ids": {
                        "terms": {"field": "event_id_keyword", "size": 10}
                    },
                    "top_computers": {
                        "terms": {"field": "computer", "size": 10}
                    },
                    "top_users": {
                        "terms": {"field": "user", "size": 10}
                    },
                    "by_mitre_tactic": {
                        "terms": {"field": "mitre_tactic", "size": 10}
                    },
                },
            },
        )

        win_aggs  = win_resp["aggregations"]
        win_total = win_resp["hits"]["total"]["value"]

        net_anomalies = net_aggs["total_anomalies"]["doc_count"]
        win_anomalies = win_aggs["total_anomalies"]["doc_count"]

        return {
            "network": {
                "total_events":      net_total,
                "total_anomalies":   net_anomalies,
                "anomaly_rate_pct":  round(net_anomalies / max(net_total, 1) * 100, 2),
                "avg_anomaly_score": round(net_aggs["avg_anomaly_score"].get("value") or 0, 4),
                "by_severity":       {b["key"]: b["doc_count"] for b in net_aggs["by_severity"]["buckets"]},
                "by_protocol":       {b["key"]: b["doc_count"] for b in net_aggs["by_protocol"]["buckets"]},
                "top_src_ips":       [{"ip": b["key"], "count": b["doc_count"]} for b in net_aggs["top_src_ips"]["buckets"]],
                "top_dst_ports":     [{"port": b["key"], "count": b["doc_count"]} for b in net_aggs["top_dst_ports"]["buckets"]],
            },
            "windows": {
                "total_events":    win_total,
                "total_anomalies": win_anomalies,
                "anomaly_rate_pct": round(win_anomalies / max(win_total, 1) * 100, 2),
                "by_severity":     {b["key"]: b["doc_count"] for b in win_aggs["by_severity"]["buckets"]},
                "top_event_ids":   [{"event_id": b["key"], "count": b["doc_count"]} for b in win_aggs["top_event_ids"]["buckets"]],
                "top_computers":   [{"host": b["key"], "count": b["doc_count"]} for b in win_aggs["top_computers"]["buckets"]],
                "top_users":       [{"user": b["key"], "count": b["doc_count"]} for b in win_aggs["top_users"]["buckets"]],
                "by_mitre_tactic": {b["key"]: b["doc_count"] for b in win_aggs["by_mitre_tactic"]["buckets"]},
            },
        }

    except Exception as e:
        logger.error(f"Stats query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
