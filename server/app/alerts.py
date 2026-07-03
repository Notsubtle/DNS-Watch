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
import time

from app import db

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

VALID_TYPES = {"volume_threshold", "new_device", "domain_keyword"}

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
            """
        )
        conn.commit()


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
