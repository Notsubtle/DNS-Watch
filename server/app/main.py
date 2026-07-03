from __future__ import annotations

import csv
import io
import os
import time

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import alerts, db

app = FastAPI(title="DNS Watch")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # LAN-only tool behind your own firewall; see README hardening notes
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
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
    rows = db.list_queries(client, domain, status, effective_since, until, limit, offset)
    total = db.count_queries(client, domain, status, effective_since, until)
    return {"total": total, "limit": limit, "offset": offset, "rows": rows}


@app.get("/api/queries.csv")
def api_queries_csv(
    client: str | None = None,
    domain: str | None = None,
    status: str | None = None,
    range: str | None = "1h",
    since: int | None = None,
    until: int | None = None,
    limit: int = Query(10000, le=100000),
):
    """Export the current query view as CSV. Higher default cap than the paged
    JSON endpoint since an export is expected to be the whole matching set."""
    effective_since = _since_from_range(range, since)
    rows = db.list_queries(client, domain, status, effective_since, until, limit, 0)

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        cols = ["timestamp", "time_utc", "client_ip", "client_name", "domain",
                "query_type", "status", "raw_status"]
        writer.writerow(cols)
        for r in rows:
            writer.writerow([
                r["timestamp"],
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["timestamp"])),
                r["client_ip"], r["client_name"], r["domain"],
                r["query_type"], r["status"], r["raw_status"],
            ])
        yield buf.getvalue()

    filename = f"dns-watch-{int(time.time())}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/query-types")
def api_query_types(client: str | None = None, range: str | None = "1h", since: int | None = None):
    effective_since = _since_from_range(range, since)
    return db.query_types(client, effective_since)


@app.get("/api/timeseries")
def api_timeseries(
    client: str | None = None,
    range: str | None = "1h",
    since: int | None = None,
    until: int | None = None,
    buckets: int = Query(60, ge=1, le=500),
):
    effective_since = _since_from_range(range, since)
    return db.timeseries(client, effective_since, until, buckets)


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


@app.get("/api/client-activity")
def api_client_activity(
    range: str | None = "1h",
    since: int | None = None,
    limit: int = Query(10, ge=1, le=50),
    buckets: int = Query(20, ge=1, le=200),
):
    effective_since = _since_from_range(range, since)
    return db.client_activity(effective_since, None, limit, buckets)


class RuleCreate(BaseModel):
    name: str
    type: str
    params: dict = {}
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    params: dict | None = None


@app.get("/api/alerts")
def api_alerts(limit: int = Query(50, ge=1, le=200)):
    """Evaluate enabled rules against current data, then return recent events."""
    fired = alerts.evaluate()
    return {"evaluated_at": int(time.time()), "new": len(fired), "events": alerts.list_events(limit)}


@app.get("/api/alert-rules")
def api_list_rules():
    return alerts.list_rules()


@app.post("/api/alert-rules")
def api_create_rule(rule: RuleCreate):
    try:
        return alerts.create_rule(rule.name, rule.type, rule.params, rule.enabled)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.patch("/api/alert-rules/{rule_id}")
def api_update_rule(rule_id: int, patch: RuleUpdate):
    updated = alerts.update_rule(
        rule_id, name=patch.name, enabled=patch.enabled, params=patch.params
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return updated


@app.delete("/api/alert-rules/{rule_id}")
def api_delete_rule(rule_id: int):
    if not alerts.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="rule not found")
    return {"deleted": rule_id}


# Serve the built frontend (Docker build copies web/dist here). In local dev,
# this path won't exist and the frontend is served separately by Vite instead.
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
