"""
=============================================================
 ThreatHunter Pro — API Dependencies (shared clients)
 api/dependencies.py
=============================================================
"""

import os
from functools import lru_cache
from elasticsearch import Elasticsearch
import redis as redis_lib
from loguru import logger

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "ThreatHunter@2024")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


@lru_cache(maxsize=1)
def get_es_client() -> Elasticsearch:
    client = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        ssl_show_warn=False,
    )
    return client


@lru_cache(maxsize=1)
def get_redis_client() -> redis_lib.Redis:
    return redis_lib.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        decode_responses=True,
    )
