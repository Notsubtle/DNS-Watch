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


def _client_ip_col() -> str:
    """The real column holding the client IP, for use in WHERE/GROUP BY.

    We filter on the underlying column rather than the `client_ip` SELECT alias
    so the same filter works in aggregate queries (COUNT(*), SUM(...)) that
    don't project the alias — SQLite only resolves output aliases in WHERE when
    they're present in the SELECT list.
    """
    return "c.ip" if detect_schema().has_client_table else "q.client"


def _status_case() -> str:
    blocked = ",".join(str(s) for s in BLOCKED_STATUSES)
    allowed = ",".join(str(s) for s in ALLOWED_STATUSES)
    return (
        f"CASE WHEN q.status IN ({blocked}) THEN 'blocked' "
        f"WHEN q.status IN ({allowed}) THEN 'allowed' "
        f"ELSE 'unknown' END AS resolved_status"
    )


def _status_where(status: str | None) -> str | None:
    """SQL predicate (no params) restricting q.status to a resolved category.

    Returns None for "all"/None so no status restriction is applied. Filtering
    in SQL (rather than post-filtering fetched rows in Python) is what lets
    LIMIT/OFFSET and COUNT(*) stay correct for status-filtered views.
    """
    if not status or status == "all":
        return None
    blocked = ",".join(str(s) for s in BLOCKED_STATUSES)
    allowed = ",".join(str(s) for s in ALLOWED_STATUSES)
    if status == "blocked":
        return f"q.status IN ({blocked})"
    if status == "allowed":
        return f"q.status IN ({allowed})"
    if status == "unknown":
        return f"q.status NOT IN ({blocked},{allowed})"
    return None


def _build_where(
    client: str | None = None,
    domain: str | None = None,
    status: str | None = None,
    since: int | None = None,
    until: int | None = None,
) -> tuple[str, list]:
    """Shared WHERE-clause builder used by every filtered query.

    Centralising this keeps list/count/summary/top-* in lockstep so a filter
    added in one place can't silently diverge from the totals shown elsewhere.
    Returns (where_sql, params); where_sql always starts with "1=1" so callers
    can drop it into `WHERE {where_sql}` unconditionally.
    """
    where = ["1=1"]
    params: list = []
    if client:
        where.append(f"{_client_ip_col()} = ?")
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
    status_pred = _status_where(status)
    if status_pred:
        where.append(status_pred)
    return " AND ".join(where), params


def list_clients() -> list[dict]:
    select, join = _client_join_sql()
    sql = f"""
        SELECT {select}, COUNT(*) AS query_count
        FROM queries q
        {join}
        GROUP BY {_client_ip_col()}
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
    where_sql, params = _build_where(client, domain, status, since, until)

    sql = f"""
        SELECT q.timestamp, q.domain, q.type, q.status, {status_case}, {select}
        FROM queries q
        {join}
        WHERE {where_sql}
        ORDER BY q.timestamp DESC
        LIMIT ? OFFSET ?
    """
    params = [*params, limit, offset]

    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()

    return [
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


def count_queries(
    client: str | None,
    domain: str | None,
    status: str | None,
    since: int | None,
    until: int | None,
) -> int:
    """Total rows matching the same filters as list_queries, ignoring paging.

    Lets the frontend show "showing 200 of 5,000" and build pager controls.
    """
    _, join = _client_join_sql()
    where_sql, params = _build_where(client, domain, status, since, until)
    sql = f"SELECT COUNT(*) AS n FROM queries q {join} WHERE {where_sql}"
    with _connect() as conn:
        return conn.execute(sql, params).fetchone()["n"]


def summary(client: str | None, since: int | None, until: int | None) -> dict:
    _, join = _client_join_sql()
    where_sql, params = _build_where(client=client, since=since, until=until)
    blocked_in = ",".join(str(s) for s in BLOCKED_STATUSES)
    client_col = _client_ip_col()

    # Aggregate in SQLite rather than pulling every matching row into Python —
    # this stays flat as retention grows (maxDBdays defaults to 365).
    sql = f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN q.status IN ({blocked_in}) THEN 1 ELSE 0 END) AS blocked,
            COUNT(DISTINCT {client_col}) AS unique_clients,
            COUNT(DISTINCT q.domain) AS unique_domains
        FROM queries q
        {join}
        WHERE {where_sql}
    """
    with _connect() as conn:
        r = conn.execute(sql, params).fetchone()

    total = r["total"] or 0
    blocked = r["blocked"] or 0
    return {
        "total_queries": total,
        "blocked": blocked,
        "blocked_pct": round((blocked / total) * 100, 1) if total else 0.0,
        "unique_clients": r["unique_clients"] or 0,
        "unique_domains": r["unique_domains"] or 0,
    }


def top_domains(client: str | None, since: int | None, limit: int = 15) -> list[dict]:
    _, join = _client_join_sql()
    where_sql, params = _build_where(client=client, since=since)

    sql = f"""
        SELECT q.domain, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {where_sql}
        GROUP BY q.domain
        ORDER BY n DESC
        LIMIT ?
    """
    params = [*params, limit]
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [{"domain": r["domain"], "count": r["n"]} for r in rows]


def top_clients(since: int | None, limit: int = 15) -> list[dict]:
    select, join = _client_join_sql()
    where_sql, params = _build_where(since=since)

    sql = f"""
        SELECT {select}, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {where_sql}
        GROUP BY {_client_ip_col()}
        ORDER BY n DESC
        LIMIT ?
    """
    params = [*params, limit]
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
