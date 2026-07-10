from __future__ import annotations

import base64
import csv
import hmac
import io
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from zoneinfo import ZoneInfoNotFoundError

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import alerts, db, names, resolve, rollups, tags

# How often the server evaluates alert rules on its own, independent of any open
# dashboard. This is what makes alerting/webhooks work headless. Set to 0 to
# disable and fall back to only-when-the-frontend-polls behaviour.
ALERT_EVAL_INTERVAL = int(os.environ.get("ALERT_EVAL_INTERVAL_SECONDS", "60"))

_scheduler_stop = threading.Event()


def _alert_scheduler() -> None:
    while not _scheduler_stop.is_set():
        try:
            alerts.evaluate()
        except Exception:  # noqa: BLE001 — never let the loop die on a transient error
            pass
        try:
            # Piggyback the rollup-cache refresh on this same tick rather than
            # running a second recurring timer — each refresh only processes
            # rows newer than its cursor, so this stays cheap regardless of
            # total table size (see app/rollups.py).
            rollups.refresh_rollups()
        except Exception:  # noqa: BLE001 — a rollup hiccup must not kill alerting
            pass
        try:
            # Piggyback the rare (default: daily) full reconciliation on the same
            # tick. It self-gates on its own last-reconciled clock, so all but one
            # tick a day is a single indexed read; on the tick it does fire it
            # rebuilds the rollup tables from scratch to erase the drift Pi-hole's
            # own row pruning otherwise leaves behind (see rollups.reconcile_rollups).
            # Its own try/except so a reconciliation failure can't block or kill
            # alerting or the incremental refresh — same contract as the two above.
            rollups.reconcile_rollups()
        except Exception:  # noqa: BLE001 — a reconciliation hiccup must not kill the loop
            pass
        try:
            # Piggyback active reverse-DNS resolution (issue: translate quiet/
            # static-IP clients Pi-hole never named into real names — see
            # app/resolve.py). Batched and backed off on its own, so this is a
            # single cheap indexed read on most ticks.
            resolve.resolve_batch(db.clients_missing_name())
        except Exception:  # noqa: BLE001 — a resolver hiccup must not kill the loop
            pass
        _scheduler_stop.wait(ALERT_EVAL_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    thread: threading.Thread | None = None
    if ALERT_EVAL_INTERVAL > 0:
        thread = threading.Thread(target=_alert_scheduler, daemon=True, name="alert-scheduler")
        thread.start()
    try:
        yield
    finally:
        _scheduler_stop.set()
        if thread is not None:
            thread.join(timeout=5)


app = FastAPI(title="DNS Watch", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # LAN-only tool behind your own firewall; see README hardening notes
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

# Optional HTTP Basic auth. Enabled only when DNSWATCH_AUTH_PASSWORD is set, so
# the default (unset) stays open for LAN use and local dev. When set, every
# route requires the credential except the health check (for container/monitor
# probes) and CORS preflight. Basic auth is cleartext-over-HTTP — put DNS Watch
# behind a TLS reverse proxy if it's reachable beyond a trusted LAN.
def _read_auth_password() -> str:
    """Prefer a password read from a file (e.g. a mounted Docker secret) over
    the plain DNSWATCH_AUTH_PASSWORD env var, so operators who want the
    credential off the process environment/`docker inspect` output have that
    option. Falls back to the env var when the file isn't configured or
    can't be read, so existing setups keep working unchanged."""
    password_file = os.environ.get("DNSWATCH_AUTH_PASSWORD_FILE")
    if password_file:
        try:
            with open(password_file, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            pass
    return os.environ.get("DNSWATCH_AUTH_PASSWORD", "")


AUTH_USERNAME = os.environ.get("DNSWATCH_AUTH_USERNAME", "admin")
AUTH_PASSWORD = _read_auth_password()


@app.middleware("http")
async def basic_auth(request, call_next):
    if not AUTH_PASSWORD or request.method == "OPTIONS" or request.url.path == "/api/health":
        return await call_next(request)
    header = request.headers.get("Authorization", "")
    if header.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
            # Compare both fields (constant-time) and AND the results so timing
            # doesn't reveal which half matched.
            if hmac.compare_digest(user, AUTH_USERNAME) & hmac.compare_digest(pw, AUTH_PASSWORD):
                return await call_next(request)
        except Exception:  # noqa: BLE001 — malformed header -> treat as unauthenticated
            pass
    return Response(
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="DNS Watch"'},
    )


_STATE_CHANGING_METHODS = {"POST", "PATCH", "DELETE"}

# GET /api/alerts is the one exception to "GET is read-only": it evaluates
# alert rules on every call (writing alert_events rows and potentially firing
# a webhook), so it needs the same cross-origin protection as an actual
# state-changing method even though its HTTP verb says otherwise. Scoped to
# just this path rather than broadening the check to every GET, which would
# risk rejecting legitimate cross-origin consumers of the many genuinely
# read-only endpoints (e.g. an external dashboard fetching queries.csv).
_MUTATING_GET_PATHS = {"/api/alerts"}


@app.middleware("http")
async def csrf_guard(request, call_next):
    """Reject cross-origin state-changing requests.

    HTTP Basic auth (when enabled) has no CSRF protection of its own — a
    browser attaches cached credentials to ANY request sent to this origin,
    including ones triggered by a page the victim merely visits. There's no
    session/cookie model here to hang a token off of, so the minimal fix is
    an Origin/Referer check: if the browser tells us where the request came
    from and it doesn't match this origin, refuse it. Requests with neither
    header (curl, server-to-server calls) are let through unchanged — this
    closes the browser-driven CSRF path, not a hardened defense against a
    client that can forge headers outright.

    Caveat for reverse-proxy deployments (the README's recommended setup for
    anything beyond a trusted LAN): this compares against whatever `Host`
    header reaches THIS process, so the proxy must forward the original
    Host unchanged (the common default for Caddy/nginx/Traefik) or
    legitimate same-origin requests get rejected here too.
    """
    if request.method in _STATE_CHANGING_METHODS or request.url.path in _MUTATING_GET_PATHS:
        source = request.headers.get("origin") or request.headers.get("referer")
        if source:
            # Reject on ANY mismatch, including an empty netloc — an opaque
            # "null" Origin (sandboxed iframes, some cross-origin redirects)
            # parses to an empty netloc and must never be treated as a free
            # pass just because it doesn't positively contradict the Host
            # header. The legitimate dashboard never sends "null" or an
            # unparseable Origin for its own same-origin requests.
            source_host = urlparse(source).netloc
            if source_host != request.headers.get("host", ""):
                return Response(status_code=403, content="cross-origin request rejected")
    return await call_next(request)


def _resolve_client_filter(
    client: str | None, tag: str | None, vendor: str | None = None
) -> str | list[str] | None:
    """Resolves the dashboard's mutually-exclusive `client`/`tag`/`vendor`
    (#11/#31) query params into the single value db.py's aggregate functions
    accept -- a plain ip, a group's member-ip list, or None for no filter.
    `tag` wins over `vendor` wins over `client` if somehow more than one is
    given (the UI only ever sends one). An unknown tag name 404s, since a tag
    is a stored entity the user creates; an unmatched vendor name just
    resolves to an empty ip list (matches nothing) rather than 404ing, since
    "vendor" isn't a stored entity -- the same silent-empty behaviour an
    unrecognized single client ip already has today."""
    if tag:
        ips = tags.get_tag_ips(tag)
        if ips is None:
            raise HTTPException(status_code=404, detail=f"no such tag: {tag!r}")
        return ips
    if vendor:
        return db.client_ips_for_vendor(vendor)
    return client


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
    tag: str | None = None,
    vendor: str | None = None,
    domain: str | None = None,
    status: str | None = None,
    range: str | None = "1h",
    since: int | None = None,
    until: int | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    who = _resolve_client_filter(client, tag, vendor)
    effective_since = _since_from_range(range, since)
    rows = db.list_queries(who, domain, status, effective_since, until, limit, offset)
    total = db.count_queries(who, domain, status, effective_since, until)
    return {"total": total, "limit": limit, "offset": offset, "rows": rows}


@app.get("/api/tail")
def api_tail(since: float, since_id: int = 0, limit: int = Query(500, ge=1, le=2000)):
    """Polling-friendly 'everything new since my last row' feed for the Live
    Stream console. No default for `since` — the frontend must pass the
    current time on first mount, or a first call would dump the client's
    entire history into the console instead of just what's new."""
    return db.tail_queries(since, since_id, limit)


class SimulateRequest(BaseModel):
    pattern: str
    range: str = "7d"


@app.post("/api/simulate-blocklist")
def api_simulate_blocklist(body: SimulateRequest):
    """Retrospective "what would this regex have blocked" — read-only, no
    path anywhere in DNS Watch applies the pattern to Pi-hole. Window is
    hard-capped at 7 days server-side regardless of what `range` requests —
    a safety property (see task README), not a UX default the client can
    widen.
    """
    if not body.pattern.strip():
        raise HTTPException(status_code=400, detail="Pattern cannot be empty")
    since = _since_from_range(body.range, None) or (int(time.time()) - 7 * 86400)
    since = max(since, int(time.time()) - 7 * 86400)
    try:
        return db.simulate_pattern(body.pattern, since)
    except re.error:
        raise HTTPException(status_code=400, detail="Invalid regular expression syntax")
    except db.SimulationBudgetExceeded as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/api/queries.csv")
def api_queries_csv(
    client: str | None = None,
    tag: str | None = None,
    vendor: str | None = None,
    domain: str | None = None,
    status: str | None = None,
    range: str | None = "1h",
    since: int | None = None,
    until: int | None = None,
    limit: int = Query(10000, ge=1, le=100000),
):
    """Export the current query view as CSV. Higher default cap than the paged
    JSON endpoint since an export is expected to be the whole matching set."""
    who = _resolve_client_filter(client, tag, vendor)
    effective_since = _since_from_range(range, since)
    rows = db.list_queries(who, domain, status, effective_since, until, limit, 0)

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
def api_query_types(
    client: str | None = None, tag: str | None = None, vendor: str | None = None,
    range: str | None = "1h", since: int | None = None,
):
    who = _resolve_client_filter(client, tag, vendor)
    effective_since = _since_from_range(range, since)
    return db.query_types(who, effective_since)


@app.get("/api/timeseries")
def api_timeseries(
    client: str | None = None,
    tag: str | None = None,
    vendor: str | None = None,
    range: str | None = "1h",
    since: int | None = None,
    until: int | None = None,
    buckets: int = Query(60, ge=1, le=500),
):
    who = _resolve_client_filter(client, tag, vendor)
    effective_since = _since_from_range(range, since)
    return db.timeseries(who, effective_since, until, buckets)


@app.get("/api/client/{ip}")
def api_client_detail(ip: str, range: str | None = "24h", since: int | None = None):
    effective_since = _since_from_range(range, since)
    return db.client_detail(ip, effective_since, None)


@app.get("/api/client/{ip}/heatmap")
def api_client_heatmap(ip: str, tz: str, days: int = Query(7, ge=1, le=30)):
    """7x24 (weekday x hour) activity grid for one client, in the caller's
    own local time — see db.client_heatmap() for the timezone handling."""
    try:
        return db.client_heatmap(ip, tz, days)
    except ZoneInfoNotFoundError:
        raise HTTPException(status_code=400, detail="Unknown timezone")


@app.get("/api/client/{ip}/heatmap/cell")
def api_client_heatmap_cell(
    ip: str, tz: str, weekday: int, hour: int, days: int = Query(7, ge=1, le=30)
):
    """The exact rows behind one heatmap cell."""
    try:
        return db.client_heatmap_cell(ip, tz, weekday, hour, days)
    except ZoneInfoNotFoundError:
        raise HTTPException(status_code=400, detail="Unknown timezone")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/summary")
def api_summary(
    client: str | None = None, tag: str | None = None, vendor: str | None = None,
    range: str | None = "1h", since: int | None = None,
):
    who = _resolve_client_filter(client, tag, vendor)
    effective_since = _since_from_range(range, since)
    return db.summary(who, effective_since, None)


@app.get("/api/top-domains")
def api_top_domains(
    client: str | None = None, tag: str | None = None, vendor: str | None = None,
    range: str | None = "1h", limit: int = 15,
):
    who = _resolve_client_filter(client, tag, vendor)
    effective_since = _since_from_range(range, None)
    return db.top_domains(who, effective_since, limit)


@app.get("/api/top-clients")
def api_top_clients(range: str | None = "1h", limit: int = 15):
    effective_since = _since_from_range(range, None)
    return db.top_clients(effective_since, limit)


@app.get("/api/domain-fanout")
def api_domain_fanout(
    range: str | None = "1h",
    since: int | None = None,
    bucket_minutes: int = Query(5, ge=1, le=60),
    min_clients: int = Query(3, ge=2, le=1000),
    limit: int = Query(50, ge=1, le=200),
):
    """Domains hit by several distinct clients within one short window (#34)
    -- see db.domain_fanout for why this is bucketed rather than a flat
    whole-range distinct-client count."""
    effective_since = _since_from_range(range, since)
    return db.domain_fanout(effective_since, None, bucket_minutes, min_clients, limit)


@app.get("/api/anomalies")
def api_anomalies():
    """Automatic silent/spike detection against each client's own 7-day
    baseline. Fixed thresholds, no params — see db.detect_anomalies()."""
    return db.detect_anomalies()


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


class SettingsUpdate(BaseModel):
    webhook_enabled: bool | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None
    webhook_format: str | None = None


class WebhookTest(BaseModel):
    url: str
    secret: str = ""
    format: str = "generic"


class DeviceNameUpdate(BaseModel):
    name: str


class TagCreate(BaseModel):
    name: str


class TagMemberAdd(BaseModel):
    ip: str


@app.get("/api/settings")
def api_get_settings():
    return alerts.get_settings()


@app.patch("/api/settings")
def api_update_settings(patch: SettingsUpdate):
    try:
        return alerts.update_settings(
            webhook_enabled=patch.webhook_enabled,
            webhook_url=patch.webhook_url,
            webhook_secret=patch.webhook_secret,
            webhook_format=patch.webhook_format,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/settings/test-webhook")
def api_test_webhook(body: WebhookTest):
    return alerts.test_webhook(body.url, body.secret, body.format)


@app.get("/api/alerts")
def api_alerts(limit: int = Query(50, ge=1, le=200)):
    """Evaluate enabled rules against current data, then return recent events."""
    fired = alerts.evaluate()
    return {"evaluated_at": int(time.time()), "new": len(fired), "events": alerts.list_events(limit)}


class SnoozeRequest(BaseModel):
    until: int  # unix ts


@app.post("/api/alert-events/{event_id}/snooze")
def api_snooze_event(event_id: int, body: SnoozeRequest):
    """Silence future recurrences of this ONE fired event's underlying
    condition (its dedup_key -- e.g. one device's new-vendor alert) until
    `until`, without touching the rule or any other client/domain it also
    watches (#42)."""
    result = alerts.snooze_event(event_id, body.until)
    if result is None:
        raise HTTPException(status_code=404, detail="event not found")
    return result


@app.delete("/api/alert-snoozes/{dedup_key}")
def api_unsnooze(dedup_key: str):
    """Lift a snooze early. The frontend must URL-encode `dedup_key` (it
    legitimately contains colons, e.g. "vendor:12:192.168.1.50" -- see
    alerts.py's dedup_key convention) when building the request URL."""
    if not alerts.unsnooze(dedup_key):
        raise HTTPException(status_code=404, detail="no active snooze for this key")
    return {"unsnoozed": dedup_key}


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


@app.get("/api/device-names")
def api_list_device_names():
    """Every ip DNS Watch knows about, with each name source broken out
    separately, for the "Manage Device Names" UI — see db.device_name_rows()."""
    return db.device_name_rows()


@app.put("/api/device-names/{ip}")
def api_set_device_name(ip: str, body: DeviceNameUpdate):
    try:
        names.set_name(ip, body.name)
    except names.InvalidName as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ip": ip, "name": body.name}


@app.delete("/api/device-names/{ip}")
def api_delete_device_name(ip: str):
    if not names.delete_name(ip):
        raise HTTPException(status_code=404, detail="no manual name set for this ip")
    return {"deleted": ip}


@app.get("/api/vendors")
def api_list_vendors():
    """Every distinct resolved vendor currently on record, each with its
    member IPs (#11) -- for the dashboard's client/tag/vendor filter. Unlike
    /api/tags, this is derived/read-only: there's nothing to create or delete,
    it just reflects whatever vendors are currently resolved."""
    return db.list_vendors()


@app.get("/api/tags")
def api_list_tags():
    """Every client tag/group on record, each with its member IPs (#31) —
    for the tag-management UI and the dashboard's client/tag filter."""
    return tags.list_tags()


@app.post("/api/tags")
def api_create_tag(body: TagCreate):
    try:
        return tags.create_tag(body.name)
    except tags.InvalidTag as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/tags/{tag_id}")
def api_delete_tag(tag_id: int):
    if not tags.delete_tag(tag_id):
        raise HTTPException(status_code=404, detail="tag not found")
    return {"deleted": tag_id}


@app.post("/api/tags/{tag_id}/members")
def api_add_tag_member(tag_id: int, body: TagMemberAdd):
    if not tags.add_member(tag_id, body.ip):
        raise HTTPException(status_code=404, detail="tag not found")
    return {"tag_id": tag_id, "ip": body.ip}


@app.delete("/api/tags/{tag_id}/members/{ip}")
def api_remove_tag_member(tag_id: int, ip: str):
    if not tags.remove_member(tag_id, ip):
        raise HTTPException(status_code=404, detail="ip is not a member of this tag")
    return {"tag_id": tag_id, "removed": ip}


# Serve the built frontend (Docker build copies web/dist here). In local dev,
# this path won't exist and the frontend is served separately by Vite instead.
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
