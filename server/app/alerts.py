"""
Alert rule engine for DNS Watch.

State (rules + fired events) lives in a SEPARATE, writable SQLite database —
never Pi-hole's FTL db, which we only ever open read-only via `db.py`. The
store path defaults to `/data/dnswatch.db` (mount a writable volume there in
Docker) and is created on first use.

Rules are evaluated on demand (when the frontend polls `/api/alerts`) against
current FTL data. Each rule type produces zero or more events; a per-key
cooldown stops the same condition from re-firing on every poll.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import urllib.request

from app import db

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

VALID_TYPES = {"volume_threshold", "new_device", "domain_keyword"}

# Webhook payload shapes. "generic" is DNS Watch's own JSON; "slack"/"discord"
# emit exactly the single field each of those incoming-webhook APIs requires.
VALID_FORMATS = {"generic", "slack", "discord"}
DISCORD_MAX = 1900  # Discord hard-limits `content` at 2000; leave headroom.
SLACK_MAX = 3000

# Default re-fire cooldown per rule type, in seconds, when the rule doesn't
# specify its own. New-device alerts get a long cooldown so a device isn't
# re-announced all day; volume/keyword track their own window.
DEFAULT_COOLDOWN = {
    "volume_threshold": 900,
    "new_device": 86400,
    "domain_keyword": 900,
}


def _connect() -> sqlite3.Connection:
    # Ensure the parent dir exists (e.g. first run against a fresh volume).
    parent = os.path.dirname(STORE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(STORE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_store() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                params TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                rule_name TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_dedup
                ON alert_events (dedup_key, created_at);
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        conn.commit()


# --------------------------------------------------------------------------
# Settings (webhook delivery)
# --------------------------------------------------------------------------

def get_settings() -> dict:
    init_store()
    with _connect() as conn:
        rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
    d = {r["key"]: r["value"] for r in rows}
    fmt = d.get("webhook_format", "generic")
    return {
        "webhook_enabled": d.get("webhook_enabled", "0") == "1",
        "webhook_url": d.get("webhook_url", ""),
        "webhook_secret": d.get("webhook_secret", ""),
        "webhook_format": fmt if fmt in VALID_FORMATS else "generic",
    }


def _put(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def update_settings(
    *,
    webhook_enabled: bool | None = None,
    webhook_url: str | None = None,
    webhook_secret: str | None = None,
    webhook_format: str | None = None,
) -> dict:
    if webhook_format is not None and webhook_format not in VALID_FORMATS:
        raise ValueError(f"unknown webhook format: {webhook_format}")
    init_store()
    with _connect() as conn:
        if webhook_enabled is not None:
            _put(conn, "webhook_enabled", "1" if webhook_enabled else "0")
        if webhook_url is not None:
            _put(conn, "webhook_url", webhook_url.strip())
        if webhook_secret is not None:
            _put(conn, "webhook_secret", webhook_secret.strip())
        if webhook_format is not None:
            _put(conn, "webhook_format", webhook_format)
        conn.commit()
    return get_settings()


def _summary(events: list[dict]) -> str:
    return "\n".join(f"[{e['severity']}] {e['message']}" for e in events)


def _wrap_payload(fmt: str, summary: str, events: list[dict]) -> dict:
    """Shape a summary string into the body the chosen receiver expects."""
    if fmt == "slack":
        # Slack incoming webhooks require a top-level `text`.
        return {"text": summary[:SLACK_MAX] or "DNS Watch alert"}
    if fmt == "discord":
        # Discord incoming webhooks require a non-empty `content` (≤ 2000 chars).
        return {"content": summary[:DISCORD_MAX] or "DNS Watch alert"}
    # Generic DNS Watch JSON. `text`/`content` still mirror the summary so a
    # generic receiver (ntfy, Home Assistant) gets a human string for free.
    return {
        "event": "dns_watch_alert",
        "count": len(events),
        "text": summary,
        "content": summary,
        "alerts": [
            {
                "rule_name": e["rule_name"],
                "type": e["type"],
                "severity": e["severity"],
                "message": e["message"],
                "created_at": e.get("created_at"),
            }
            for e in events
        ],
    }


def deliver_webhook(
    url: str, payload: dict, secret: str = "", timeout: float = 5.0
) -> tuple[bool, str | None]:
    """POST the payload as JSON. Returns (ok, error). Never raises — delivery
    problems must not affect alert evaluation or the API response.

    A non-empty `secret` is sent as `Authorization: Bearer <secret>`, which
    covers ntfy access tokens and any receiver that checks a bearer credential.
    """
    if not url:
        return False, "no webhook URL configured"
    try:
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — user-supplied LAN URL
            ok = 200 <= resp.status < 300
            return ok, None if ok else f"HTTP {resp.status}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def test_webhook(url: str, secret: str = "", fmt: str = "generic") -> dict:
    """Synchronous test send so the settings UI can report success/failure."""
    if fmt not in VALID_FORMATS:
        fmt = "generic"
    summary = "DNS Watch test alert — your webhook is configured correctly."
    payload = _wrap_payload(fmt, summary, [])
    if fmt == "generic":
        payload["event"] = "dns_watch_test"
    ok, err = deliver_webhook(url, payload, secret)
    return {"ok": ok, "error": err}


# --------------------------------------------------------------------------
# Rule CRUD
# --------------------------------------------------------------------------

def _row_to_rule(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "type": r["type"],
        "enabled": bool(r["enabled"]),
        "params": json.loads(r["params"]),
        "created_at": r["created_at"],
    }


def list_rules() -> list[dict]:
    init_store()
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM alert_rules ORDER BY created_at").fetchall()
    return [_row_to_rule(r) for r in rows]


def create_rule(name: str, type: str, params: dict, enabled: bool = True) -> dict:
    if type not in VALID_TYPES:
        raise ValueError(f"unknown rule type: {type}")
    init_store()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO alert_rules (name, type, enabled, params, created_at) VALUES (?,?,?,?,?)",
            (name, type, 1 if enabled else 0, json.dumps(params or {}), int(time.time())),
        )
        conn.commit()
        rid = cur.lastrowid
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rid,)).fetchone()
    return _row_to_rule(row)


def update_rule(rule_id: int, *, name=None, enabled=None, params=None) -> dict | None:
    init_store()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if not row:
            return None
        new_name = name if name is not None else row["name"]
        new_enabled = (1 if enabled else 0) if enabled is not None else row["enabled"]
        new_params = json.dumps(params) if params is not None else row["params"]
        conn.execute(
            "UPDATE alert_rules SET name=?, enabled=?, params=? WHERE id=?",
            (new_name, new_enabled, new_params, rule_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
    return _row_to_rule(row)


def delete_rule(rule_id: int) -> bool:
    init_store()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        conn.commit()
    return cur.rowcount > 0


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def _recently_fired(conn: sqlite3.Connection, dedup_key: str, cooldown: int, now: int) -> bool:
    row = conn.execute(
        "SELECT created_at FROM alert_events WHERE dedup_key = ? ORDER BY created_at DESC LIMIT 1",
        (dedup_key,),
    ).fetchone()
    return bool(row) and (now - row["created_at"]) < cooldown


def _emit(pending: list[dict], rule: dict, severity: str, message: str, dedup_key: str) -> None:
    pending.append({
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "type": rule["type"],
        "severity": severity,
        "message": message,
        "dedup_key": dedup_key,
    })


def _eval_rule(rule: dict, now: int, pending: list[dict]) -> None:
    p = rule["params"]
    if rule["type"] == "volume_threshold":
        window_min = int(p.get("window_minutes", 5))
        threshold = int(p.get("threshold", 1000))
        since = now - window_min * 60
        scope = p.get("scope", "any")
        if scope == "per_client":
            for c in db.top_clients(since, limit=100):
                if c["count"] >= threshold:
                    _emit(pending, rule, "warning",
                          f"{c['name']} made {c['count']} queries in {window_min}m "
                          f"(≥ {threshold})",
                          f"vol:{rule['id']}:{c['ip']}")
        else:
            client = p.get("client") or None
            total = db.summary(client, since, None)["total_queries"]
            if total >= threshold:
                who = client or "all clients"
                _emit(pending, rule, "warning",
                      f"{total} queries from {who} in {window_min}m (≥ {threshold})",
                      f"vol:{rule['id']}:{client or 'any'}")

    elif rule["type"] == "new_device":
        window_min = int(p.get("window_minutes", 1440))
        since = now - window_min * 60
        for c in db.new_clients(since):
            _emit(pending, rule, "info",
                  f"New device seen: {c['name']} ({c['ip']})",
                  f"new:{rule['id']}:{c['ip']}")

    elif rule["type"] == "domain_keyword":
        keyword = (p.get("keyword") or "").strip()
        if not keyword:
            return
        window_min = int(p.get("window_minutes", 60))
        min_count = int(p.get("min_count", 1))
        since = now - window_min * 60
        count = db.count_queries(None, keyword, None, since, None)
        if count >= min_count:
            _emit(pending, rule, "warning",
                  f'{count} queries matching "{keyword}" in {window_min}m (≥ {min_count})',
                  f"kw:{rule['id']}")


def evaluate() -> list[dict]:
    """Evaluate all enabled rules; persist and return newly-fired events."""
    init_store()
    now = int(time.time())
    rules = [r for r in list_rules() if r["enabled"]]
    pending: list[dict] = []
    for rule in rules:
        try:
            _eval_rule(rule, now, pending)
        except Exception:  # noqa: BLE001 — one broken rule shouldn't kill the rest
            continue

    fired: list[dict] = []
    with _connect() as conn:
        for ev in pending:
            cooldown = DEFAULT_COOLDOWN.get(ev["type"], 900)
            if _recently_fired(conn, ev["dedup_key"], cooldown, now):
                continue
            conn.execute(
                "INSERT INTO alert_events (rule_id, rule_name, type, severity, message, dedup_key, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (ev["rule_id"], ev["rule_name"], ev["type"], ev["severity"],
                 ev["message"], ev["dedup_key"], now),
            )
            fired.append({**ev, "created_at": now})
        conn.commit()

    # Push newly-fired alerts out-of-band if a webhook is enabled. Done on a
    # daemon thread so a slow or unreachable endpoint can't stall the /api/alerts
    # response (which the dashboard polls every few seconds).
    if fired:
        settings = get_settings()
        if settings["webhook_enabled"] and settings["webhook_url"]:
            payload = _wrap_payload(settings["webhook_format"], _summary(fired), fired)
            threading.Thread(
                target=deliver_webhook,
                args=(settings["webhook_url"], payload, settings["webhook_secret"]),
                daemon=True,
            ).start()

    return fired


def list_events(limit: int = 50) -> list[dict]:
    init_store()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_events ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "id": r["id"],
            "rule_id": r["rule_id"],
            "rule_name": r["rule_name"],
            "type": r["type"],
            "severity": r["severity"],
            "message": r["message"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
