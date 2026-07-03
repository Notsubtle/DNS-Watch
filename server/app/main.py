from __future__ import annotations

import os
import time

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import db

app = FastAPI(title="DNS Watch")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # LAN-only tool behind your own firewall; see README hardening notes
    allow_methods=["GET"],
    allow_headers=["*"],
)


def _since_from_range(range_param: str | None, since_param: int | None) -> int | None:
    """Accepts either an explicit unix `since` or a relative `range` like '1h','24h','7d','15m'."""
    if since_param:
        return since_param
    if not range_param or range_param == "all":
        return None
    unit = range_param[-1]
    try:
        n = int(range_param[:-1])
    except ValueError:
        return None
    seconds = {"m": 60, "h": 3600, "d": 86400}.get(unit)
    if not seconds:
        return None
    return int(time.time()) - n * seconds


@app.get("/api/health")
def api_health():
    return db.health()


@app.get("/api/clients")
def api_clients():
    return db.list_clients()


@app.get("/api/queries")
def api_queries(
    client: str | None = None,
    domain: str | None = None,
    status: str | None = None,
    range: str | None = "1h",
    since: int | None = None,
    until: int | None = None,
    limit: int = Query(200, le=1000),
    offset: int = 0,
):
    effective_since = _since_from_range(range, since)
    return db.list_queries(client, domain, status, effective_since, until, limit, offset)


@app.get("/api/summary")
def api_summary(client: str | None = None, range: str | None = "1h", since: int | None = None):
    effective_since = _since_from_range(range, since)
    return db.summary(client, effective_since, None)


@app.get("/api/top-domains")
def api_top_domains(client: str | None = None, range: str | None = "1h", limit: int = 15):
    effective_since = _since_from_range(range, None)
    return db.top_domains(client, effective_since, limit)


@app.get("/api/top-clients")
def api_top_clients(range: str | None = "1h", limit: int = 15):
    effective_since = _since_from_range(range, None)
    return db.top_clients(effective_since, limit)


# Serve the built frontend (Docker build copies web/dist here). In local dev,
# this path won't exist and the frontend is served separately by Vite instead.
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
