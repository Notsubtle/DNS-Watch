"""
Read-only access layer for Pi-hole's FTL SQLite database.

This module NEVER opens the database for writing. Every connection is opened
with `mode=ro` in the URI so that even a bug here can't corrupt or lock
Pi-hole's live query log.

Pi-hole's schema has changed across major versions:
  - Older FTL: `queries` table has a `client` column holding the client's IP
    directly as text. Names (if any) live in a separate `network` table
    keyed by IP/hwaddr.
  - Newer FTL (v6+): `queries` has a `client_id` foreign key into a `client`
    table (id, ip, name, ...).

`detect_schema()` inspects the live DB once per process and picks the right
query shape, so this works across Pi-hole versions without configuration.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from functools import lru_cache

DB_PATH = os.environ.get("PIHOLE_DB_PATH", "/pihole-data/pihole-FTL.db")

# Best-effort classification of Pi-hole FTL's internal query status codes.
# Raw status is always returned alongside so a mismatch is visible, not hidden.
BLOCKED_STATUSES = {1, 4, 5, 6, 7, 8, 9, 10, 11, 16, 18, 19, 20, 21, 22, 23, 24, 25}
ALLOWED_STATUSES = {2, 3, 12, 13, 17}
# Anything not in either set above is reported as "unknown" rather than guessed.


@dataclass(frozen=True)
class Schema:
    has_client_table: bool  # True = newer FTL (client_id -> client table)


def _connect() -> sqlite3.Connection:
    uri = f"file:{DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


@lru_cache(maxsize=1)
def detect_schema() -> Schema:
    with _connect() as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(queries)")}
        has_client_table = "client_id" in cols
    return Schema(has_client_table=has_client_table)


def _client_join_sql() -> tuple[str, str]:
    """Returns (select_fragment, join_fragment) for client identity + name."""
    schema = detect_schema()
    if schema.has_client_table:
        select = "c.ip AS client_ip, c.name AS client_name"
        join = "LEFT JOIN client c ON c.id = q.client_id"
    else:
        select = "q.client AS client_ip, n.name AS client_name"
        join = (
            "LEFT JOIN network_addresses na ON na.ip = q.client "
            "LEFT JOIN network n ON n.id = na.network_id"
        )
    return select, join


def _status_case() -> str:
    blocked = ",".join(str(s) for s in BLOCKED_STATUSES)
    allowed = ",".join(str(s) for s in ALLOWED_STATUSES)
    return (
        f"CASE WHEN q.status IN ({blocked}) THEN 'blocked' "
        f"WHEN q.status IN ({allowed}) THEN 'allowed' "
        f"ELSE 'unknown' END AS resolved_status"
    )


def list_clients() -> list[dict]:
    select, join = _client_join_sql()
    sql = f"""
        SELECT {select}, COUNT(*) AS query_count
        FROM queries q
        {join}
        GROUP BY client_ip
        ORDER BY query_count DESC
    """
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
    return [
        {
            "ip": r["client_ip"],
            "name": r["client_name"] or r["client_ip"],
            "query_count": r["query_count"],
        }
        for r in rows
    ]


def list_queries(
    client: str | None,
    domain: str | None,
    status: str | None,
    since: int | None,
    until: int | None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    select, join = _client_join_sql()
    status_case = _status_case()
    where = ["1=1"]
    params: list = []

    if client:
        where.append("client_ip = ?")
        params.append(client)
    if domain:
        where.append("q.domain LIKE ?")
        params.append(f"%{domain}%")
    if since:
        where.append("q.timestamp >= ?")
        params.append(since)
    if until:
        where.append("q.timestamp <= ?")
        params.append(until)

    sql = f"""
        SELECT q.timestamp, q.domain, q.type, q.status, {status_case}, {select}
        FROM queries q
        {join}
        WHERE {' AND '.join(where)}
        ORDER BY q.timestamp DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])

    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()

    results = [
        {
            "timestamp": r["timestamp"],
            "domain": r["domain"],
            "query_type": r["type"],
            "raw_status": r["status"],
            "status": r["resolved_status"],
            "client_ip": r["client_ip"],
            "client_name": r["client_name"] or r["client_ip"],
        }
        for r in rows
    ]

    if status and status != "all":
        results = [r for r in results if r["status"] == status]

    return results


def summary(client: str | None, since: int | None, until: int | None) -> dict:
    select, join = _client_join_sql()
    status_case = _status_case()
    where = ["1=1"]
    params: list = []
    if client:
        where.append("client_ip = ?")
        params.append(client)
    if since:
        where.append("q.timestamp >= ?")
        params.append(since)
    if until:
        where.append("q.timestamp <= ?")
        params.append(until)

    sql = f"""
        SELECT {status_case}, {select}, q.domain
        FROM queries q
        {join}
        WHERE {' AND '.join(where)}
    """
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()

    total = len(rows)
    blocked = sum(1 for r in rows if r["resolved_status"] == "blocked")
    unique_clients = len({r["client_ip"] for r in rows})
    unique_domains = len({r["domain"] for r in rows})

    return {
        "total_queries": total,
        "blocked": blocked,
        "blocked_pct": round((blocked / total) * 100, 1) if total else 0.0,
        "unique_clients": unique_clients,
        "unique_domains": unique_domains,
    }


def top_domains(client: str | None, since: int | None, limit: int = 15) -> list[dict]:
    select, join = _client_join_sql()
    where = ["1=1"]
    params: list = []
    if client:
        where.append("client_ip = ?")
        params.append(client)
    if since:
        where.append("q.timestamp >= ?")
        params.append(since)

    sql = f"""
        SELECT q.domain, {select}, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {' AND '.join(where)}
        GROUP BY q.domain
        ORDER BY n DESC
        LIMIT ?
    """
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [{"domain": r["domain"], "count": r["n"]} for r in rows]


def top_clients(since: int | None, limit: int = 15) -> list[dict]:
    select, join = _client_join_sql()
    where = ["1=1"]
    params: list = []
    if since:
        where.append("q.timestamp >= ?")
        params.append(since)

    sql = f"""
        SELECT {select}, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {' AND '.join(where)}
        GROUP BY client_ip
        ORDER BY n DESC
        LIMIT ?
    """
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [
        {"ip": r["client_ip"], "name": r["client_name"] or r["client_ip"], "count": r["n"]}
        for r in rows
    ]


def health() -> dict:
    try:
        with _connect() as conn:
            conn.execute("SELECT 1 FROM queries LIMIT 1")
        return {"ok": True, "db_path": DB_PATH, "checked_at": int(time.time())}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "db_path": DB_PATH, "error": str(e)}
