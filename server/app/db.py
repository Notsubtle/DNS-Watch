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

import math
import os
import re
import sqlite3
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DB_PATH = os.environ.get("PIHOLE_DB_PATH", "/pihole-data/pihole-FTL.db")

# Best-effort classification of Pi-hole FTL's internal query status codes.
# Raw status is always returned alongside so a mismatch is visible, not hidden.
BLOCKED_STATUSES = {1, 4, 5, 6, 7, 8, 9, 10, 11, 16, 18, 19, 20, 21, 22, 23, 24, 25}
ALLOWED_STATUSES = {2, 3, 12, 13, 17}
# Anything not in either set above is reported as "unknown" rather than guessed.

# FTL's internal query-type enumeration (NOT DNS qtype numbers). Codes outside
# this map are surfaced as "TYPE<n>" so a schema change shows up rather than
# silently mislabelling.
TYPE_NAMES = {
    1: "A", 2: "AAAA", 3: "ANY", 4: "SRV", 5: "SOA", 6: "PTR", 7: "TXT",
    8: "NAPTR", 9: "MX", 10: "DS", 11: "RRSIG", 12: "DNSKEY", 13: "NS",
    14: "OTHER", 15: "SVCB", 16: "HTTPS",
}


def type_name(code: int | None) -> str:
    if code is None:
        return "?"
    return TYPE_NAMES.get(code, f"TYPE{code}")


@dataclass(frozen=True)
class Schema:
    has_client_table: bool  # True = newer FTL (client_id -> client table)
    # Real Pi-hole v6 keeps the client NAME on `network_addresses.name` (the
    # `network` table has no name column). Older builds we've seen put the name
    # on `network.name`. Detect which so the old-schema join reads the right one.
    na_has_name: bool = False


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
        na_cols = {row["name"] for row in conn.execute("PRAGMA table_info(network_addresses)")}
        na_has_name = "name" in na_cols
    return Schema(has_client_table=has_client_table, na_has_name=na_has_name)


def _client_join_sql() -> tuple[str, str]:
    """Returns (select_fragment, join_fragment) for client identity + name."""
    schema = detect_schema()
    if schema.has_client_table:
        select = "c.ip AS client_ip, c.name AS client_name"
        join = "LEFT JOIN client c ON c.id = q.client_id"
    elif schema.na_has_name:
        # Real Pi-hole v6: the name lives on network_addresses.name (keyed by ip);
        # the `network` table has no name column, so don't join it.
        select = "q.client AS client_ip, na.name AS client_name"
        join = "LEFT JOIN network_addresses na ON na.ip = q.client"
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


def tail_queries(since: float, since_id: int, limit: int = 500) -> list[dict]:
    """Everything strictly after the cursor (since, since_id), ascending —
    the shape a polling "tail -f" console needs (give me only what's new),
    as opposed to list_queries()'s backwards-paged view (give me the latest
    N, most recent first).

    Uses a COMPOUND cursor, not timestamp alone: real Pi-hole timestamps are
    REAL/float (see the 2026-07-04 float-timestamp bucketing fix), so two
    distinct rows can share one. `id` is the table's own primary key, so
    `(timestamp, id)` together are airtight — no row is ever skipped or
    double-delivered across polls, even with a rapid burst of same-timestamp
    inserts.
    """
    select, join = _client_join_sql()
    status_case = _status_case()
    sql = f"""
        SELECT q.id, q.timestamp, q.domain, q.type, q.status, {status_case}, {select}
        FROM queries q
        {join}
        WHERE (q.timestamp > ?) OR (q.timestamp = ? AND q.id > ?)
        ORDER BY q.timestamp ASC, q.id ASC
        LIMIT ?
    """
    with _connect() as conn:
        rows = conn.execute(sql, [since, since, since_id, limit]).fetchall()
    return [
        {
            "id": r["id"],
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


def query_types(client: str | None, since: int | None, until: int | None = None) -> list[dict]:
    """Count of queries grouped by FTL query type, most frequent first."""
    _, join = _client_join_sql()
    where_sql, params = _build_where(client=client, since=since, until=until)
    sql = f"""
        SELECT q.type AS type_code, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {where_sql}
        GROUP BY q.type
        ORDER BY n DESC
    """
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [
        {"type_code": r["type_code"], "type": type_name(r["type_code"]), "count": r["n"]}
        for r in rows
    ]


def timeseries(
    client: str | None,
    since: int | None,
    until: int | None,
    buckets: int = 60,
) -> dict:
    """Allowed/blocked query counts bucketed evenly across the time window.

    Returns fixed-width buckets (including empty ones) so the frontend can draw
    a continuous chart without inferring gaps. When `since` is unknown (range
    "all"), the window is derived from the data's own min/max timestamp.
    """
    _, join = _client_join_sql()
    blocked_in = ",".join(str(s) for s in BLOCKED_STATUSES)
    allowed_in = ",".join(str(s) for s in ALLOWED_STATUSES)

    # Resolve the window. `until` defaults to now; `since` falls back to the
    # earliest matching row so "all" still produces a bounded chart.
    win_until = until if until else int(time.time())
    if since:
        win_since = since
    else:
        base_where, base_params = _build_where(client=client, until=until)
        with _connect() as conn:
            row = conn.execute(
                f"SELECT MIN(q.timestamp) AS mn FROM queries q {join} WHERE {base_where}",
                base_params,
            ).fetchone()
        win_since = row["mn"] if row and row["mn"] is not None else win_until

    span = max(1, win_until - win_since)
    buckets = max(1, min(buckets, 500))
    width = max(1, span // buckets)

    where_sql, params = _build_where(client=client, since=win_since, until=win_until)
    # Integer-divide the timestamp into bucket indexes, aggregate per bucket.
    # Real Pi-hole v6 stores q.timestamp as REAL (fractional seconds); without the
    # CAST, SQLite does float division and yields fractional bucket ids that never
    # match the integer bucket indexes we look up below (every bucket reads 0).
    sql = f"""
        SELECT
            CAST((q.timestamp - ?) / ? AS INTEGER) AS bucket,
            SUM(CASE WHEN q.status IN ({allowed_in}) THEN 1 ELSE 0 END) AS allowed,
            SUM(CASE WHEN q.status IN ({blocked_in}) THEN 1 ELSE 0 END) AS blocked,
            COUNT(*) AS total
        FROM queries q
        {join}
        WHERE {where_sql}
        GROUP BY bucket
        ORDER BY bucket
    """
    with _connect() as conn:
        rows = conn.execute(sql, [win_since, width, *params]).fetchall()

    by_bucket = {r["bucket"]: r for r in rows}
    n = int((span // width)) + 1
    series = []
    for i in range(n):
        r = by_bucket.get(i)
        series.append({
            "t": win_since + i * width,
            "allowed": (r["allowed"] if r else 0) or 0,
            "blocked": (r["blocked"] if r else 0) or 0,
            "total": (r["total"] if r else 0) or 0,
        })
    return {"since": win_since, "until": win_until, "bucket_seconds": width, "series": series}


def client_activity(
    since: int | None,
    until: int | None,
    limit: int = 10,
    buckets: int = 20,
) -> list[dict]:
    """Top clients in the window, each with a sparkline and a global first-seen.

    `first_seen` is the earliest timestamp for that client across the WHOLE db
    (not just the window), so the frontend can flag genuinely-new devices rather
    than ones that merely happen to be quiet earlier in the range.
    """
    select, join = _client_join_sql()
    ccol = _client_ip_col()

    win_until = until if until else int(time.time())
    if since:
        win_since = since
    else:
        base_where, base_params = _build_where(until=until)
        with _connect() as conn:
            mn = conn.execute(
                f"SELECT MIN(q.timestamp) AS mn FROM queries q {join} WHERE {base_where}",
                base_params,
            ).fetchone()["mn"]
        win_since = mn if mn is not None else win_until

    span = max(1, win_until - win_since)
    buckets = max(1, min(buckets, 200))
    width = max(1, span // buckets)
    n_buckets = int(span // width) + 1

    where_sql, params = _build_where(since=win_since, until=win_until)
    with _connect() as conn:
        # 1) Top N clients in the window.
        top = conn.execute(
            f"""
            SELECT {select}, COUNT(*) AS n, MAX(q.timestamp) AS last_seen
            FROM queries q
            {join}
            WHERE {where_sql}
            GROUP BY {ccol}
            ORDER BY n DESC
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()

        if not top:
            return []

        ips = [t["client_ip"] for t in top]
        placeholders = ",".join("?" for _ in ips)

        # 2) Global first-seen for just those clients (one grouped query).
        firsts = {
            r["ipcol"]: r["fs"]
            for r in conn.execute(
                f"""
                SELECT {ccol} AS ipcol, MIN(q.timestamp) AS fs
                FROM queries q
                {join}
                WHERE {ccol} IN ({placeholders})
                GROUP BY {ccol}
                """,
                ips,
            ).fetchall()
        }

        # 3) Sparkline buckets for all top clients at once.
        spark_rows = conn.execute(
            f"""
            SELECT {ccol} AS ipcol, CAST((q.timestamp - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS n
            FROM queries q
            {join}
            WHERE {where_sql} AND {ccol} IN ({placeholders})
            GROUP BY ipcol, bucket
            """,
            [win_since, width, *params, *ips],
        ).fetchall()

    spark_by_ip: dict = {}
    for r in spark_rows:
        spark_by_ip.setdefault(r["ipcol"], {})[r["bucket"]] = r["n"]

    result = []
    for t in top:
        ip = t["client_ip"]
        bmap = spark_by_ip.get(ip, {})
        result.append({
            "ip": ip,
            "name": t["client_name"] or ip,
            "count": t["n"],
            "first_seen": firsts.get(ip),
            "last_seen": t["last_seen"],
            "sparkline": [bmap.get(i, 0) for i in range(n_buckets)],
        })
    return result


def client_counts(since: int | None, until: int | None) -> list[dict]:
    """Per-client query counts within a window. Used by the device-quiet rule to
    compare a client's activity across two adjacent windows."""
    select, join = _client_join_sql()
    where_sql, params = _build_where(since=since, until=until)
    sql = f"""
        SELECT {select}, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {where_sql}
        GROUP BY {_client_ip_col()}
    """
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [
        {"ip": r["client_ip"], "name": r["client_name"] or r["client_ip"], "count": r["n"]}
        for r in rows
    ]


def client_detail(ip: str, since: int | None, until: int | None) -> dict:
    """Everything the per-client page needs: windowed summary, top domains,
    query types, and time-series, plus the client's global first/last-seen."""
    select, join = _client_join_sql()
    ccol = _client_ip_col()
    # MIN/MAX over all of this client's rows; client_name is constant within the
    # WHERE so selecting it un-grouped is safe.
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {select}, MIN(q.timestamp) AS fs, MAX(q.timestamp) AS ls "
            f"FROM queries q {join} WHERE {ccol} = ?",
            [ip],
        ).fetchone()
    name = row["client_name"] if row and row["client_name"] else ip
    return {
        "ip": ip,
        "name": name,
        "first_seen": row["fs"] if row else None,
        "last_seen": row["ls"] if row else None,
        "summary": summary(ip, since, until),
        "top_domains": top_domains(ip, since, limit=10),
        "query_types": query_types(ip, since, until),
        "timeseries": timeseries(ip, since, until, buckets=40),
    }


def _local_offset_seconds(tz_name: str) -> float:
    """UTC offset (seconds) for "now" in `tz_name`.

    Computed once per call, not per row — see tasks/04-client-heatmap's
    README for the accepted DST simplification: a single 7-day window
    crosses at most one DST transition, at most twice a year, and this is a
    home-network diagnostic tool, not a compliance system. Raises
    `zoneinfo.ZoneInfoNotFoundError` for ANY bad tz string; callers let this
    propagate so `main.py` can turn it into a 400 rather than guessing a
    fallback zone.
    """
    try:
        tz = ZoneInfo(tz_name)
    except ValueError as e:
        # ZoneInfo raises ValueError (NOT ZoneInfoNotFoundError) for keys with
        # path-traversal / absolute-path shapes, e.g. "../../etc". Normalize to
        # the not-found type so every caller only has to handle one "bad tz"
        # exception, and so the raw internal message never leaks to the client.
        raise ZoneInfoNotFoundError(f"No time zone found with key {tz_name}") from e
    return datetime.now(tz).utcoffset().total_seconds()


def client_heatmap(client_ip: str, tz_name: str, days: int = 7) -> dict:
    """One client's queries bucketed into a 7(weekday) x 24(hour) grid, in
    the caller's local time (see `_local_offset_seconds`).

    `weekday` follows Python's `datetime.weekday()` convention: Monday=0,
    Sunday=6 — the frontend must use the same convention when labeling rows,
    not the JS `Date.getDay()` convention (Sunday=0).
    """
    offset = _local_offset_seconds(tz_name)
    now = time.time()
    since = now - days * 86400

    _, join = _client_join_sql()
    where_sql, params = _build_where(client=client_ip, since=since, until=now)
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT q.timestamp FROM queries q {join} WHERE {where_sql}", params
        ).fetchall()

    grid = [[0] * 24 for _ in range(7)]
    for r in rows:
        local_dt = datetime.fromtimestamp(r["timestamp"] + offset, tz=timezone.utc)
        grid[local_dt.weekday()][local_dt.hour] += 1

    return {
        "tz": tz_name,
        "days": days,
        "grid": grid,
        "max": max((c for row in grid for c in row), default=0),
    }


def client_heatmap_cell(
    client_ip: str, tz_name: str, weekday: int, hour: int, days: int = 7
) -> list[dict]:
    """The exact rows behind one heatmap cell — built on top of the existing
    `list_queries()` rather than a new query shape, per the task plan.

    Uses the SAME offset computation as `client_heatmap()` (never re-derived
    here) so the two can never silently drift apart. A window wider than 7
    days can contain more than one occurrence of the requested weekday, so
    every local calendar day in the window is walked to find every matching
    occurrence — not just the most recent one — which is what makes the
    round-trip property hold: summing every cell's drill-down row count
    across all 168 cells equals the client's total query count in the
    window.
    """
    if not (0 <= weekday <= 6):
        raise ValueError("weekday must be between 0 (Monday) and 6 (Sunday)")
    if not (0 <= hour <= 23):
        raise ValueError("hour must be between 0 and 23")

    offset = _local_offset_seconds(tz_name)
    now = time.time()
    since = now - days * 86400
    since_local = since + offset
    until_local = now + offset

    rows: list[dict] = []
    day_start = math.floor(since_local / 86400) * 86400
    while day_start < until_local:
        if datetime.fromtimestamp(day_start, tz=timezone.utc).weekday() == weekday:
            local_hour_start = day_start + hour * 3600
            utc_start = max(local_hour_start - offset, since)
            utc_end = min(local_hour_start + 3600 - offset, now)
            if utc_start < utc_end:
                rows.extend(list_queries(client_ip, None, None, utc_start, utc_end, limit=10000))
        day_start += 86400

    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows


def new_clients(after_ts: int) -> list[dict]:
    """Clients whose *first-ever* query is at or after `after_ts`.

    First-seen is the global MIN timestamp per client, so this surfaces devices
    that genuinely appeared for the first time in the window — the signal the
    new-device alert rule keys on.
    """
    select, join = _client_join_sql()
    ccol = _client_ip_col()
    sql = f"""
        SELECT {select}, MIN(q.timestamp) AS first_seen, COUNT(*) AS total
        FROM queries q
        {join}
        GROUP BY {ccol}
        HAVING MIN(q.timestamp) >= ?
        ORDER BY first_seen DESC
    """
    with _connect() as conn:
        rows = conn.execute(sql, [after_ts]).fetchall()
    return [
        {
            "ip": r["client_ip"],
            "name": r["client_name"] or r["client_ip"],
            "first_seen": r["first_seen"],
            "total": r["total"],
        }
        for r in rows
    ]


TOP_DOMAINS_LIMIT = 50  # how many matched domains the breakdown returns


def simulate_pattern(pattern: str, since: int) -> dict:
    """Retrospective "how much of the last N days would this Pi-hole-style
    regex have blocked" — a read-only counterfactual. Never applies the
    pattern anywhere; DNS Watch has no path that writes a blocklist rule
    back to Pi-hole.

    SQLite has no built-in REGEXP; `create_function` registers one scoped to
    THIS connection only, per the module docstring — every other query in
    this file stays exactly as fast as it is today. `re.compile()` runs
    before any SQL so a malformed pattern fails fast with `re.error`, which
    `main.py` maps to a clean 400 rather than a 500 raised mid-query.

    Every number here is EXACT, including the per-client `matched_count` /
    `pct_of_client_traffic` (the spec's "accounts for X% of your SmartFridge"
    figure). This is done with two GROUP-BY aggregates — one over domain, one
    over client — rather than materializing a capped sample of matching rows
    into Python: an earlier version fetched `LIMIT 10000` raw rows and counted
    them in Python, which silently under-reported per-client impact by however
    many times `total_matches` exceeded 10000 (e.g. ~4x low for a `gstatic`
    pattern matching 44k rows). GROUP BY costs the SAME two REGEXP-evaluating
    table scans the capped version did — just aggregated in SQL and correct.
    """
    compiled = re.compile(pattern)

    def _regexp(_pattern_arg: str, value: str | None) -> int:
        return 1 if compiled.search(value or "") else 0

    select, join = _client_join_sql()
    where_sql = "q.timestamp >= ? AND q.domain REGEXP ?"

    with _connect() as conn:
        conn.create_function("REGEXP", 2, _regexp)

        # Scan 1: exact per-domain counts. total_matches (sum) and
        # unique_domains (row count) both fall out of this, so no separate
        # COUNT query is needed.
        domain_rows = conn.execute(
            f"SELECT q.domain AS domain, COUNT(*) AS n "
            f"FROM queries q {join} WHERE {where_sql} GROUP BY q.domain",
            [since, pattern],
        ).fetchall()

        # Scan 2: exact per-client matched counts.
        client_rows = conn.execute(
            f"SELECT {select}, COUNT(*) AS n "
            f"FROM queries q {join} WHERE {where_sql} GROUP BY {_client_ip_col()}",
            [since, pattern],
        ).fetchall()

    total_matches = sum(r["n"] for r in domain_rows)
    unique_domains = len(domain_rows)
    top_domains_list = sorted(
        ({"domain": r["domain"], "count": r["n"]} for r in domain_rows),
        key=lambda x: x["count"],
        reverse=True,
    )[:TOP_DOMAINS_LIMIT]

    # Reuse the existing per-client totals helper rather than re-deriving
    # "how much does this client talk overall in this window" from scratch.
    client_totals = {c["ip"]: c["count"] for c in client_counts(since, None)}
    clients = []
    for r in client_rows:
        ip = r["client_ip"]
        matched = r["n"]
        total = client_totals.get(ip, matched)
        clients.append({
            "ip": ip,
            "name": r["client_name"] or ip,
            "matched_count": matched,
            "total_count": total,
            "pct_of_client_traffic": round(matched / total * 100, 1) if total else 0.0,
        })
    clients.sort(key=lambda c: c["pct_of_client_traffic"], reverse=True)

    return {
        "pattern": pattern,
        "since": since,
        "total_matches": total_matches,
        "unique_domains": unique_domains,
        "top_domains": top_domains_list,
        "clients": clients,
    }


# --------------------------------------------------------------------------
# Anomaly detection ("Silent Talker") — automatic, unconfigurable in v1.
#
# Deliberately NOT part of alerts.py's rule engine: that module is for
# user-configured rules with webhook delivery, cooldowns, and persisted
# state. This is always-on, fixed-threshold, UI-only analytics — same shape
# as timeseries()/client_activity() above, no new database, no webhook path.
# --------------------------------------------------------------------------

BASELINE_DAYS = 7
SILENT_WINDOW_HOURS = 3
SILENT_MIN_BASELINE_AVG = 10.0  # queries/hr — this bar *is* the low-volume
                                # whitelist; a smart scale averaging 1-2/day
                                # never clears it, so no separate config needed.
SPIKE_STDDEV_MULTIPLIER = 3.0
NEW_DEVICE_GRACE_SECONDS = 24 * 3600


def detect_anomalies() -> list[dict]:
    """Flag clients whose recent query volume deviates from their own 7-day
    hourly baseline: gone silent, or spiking. Fixed thresholds (module
    constants above), not user-configurable in v1 — see tasks/01-anomaly-detection.

    Runs ONE query for the whole 7-day+recent window, grouped by (client,
    hour), rather than looping 2 queries per client. Pi-hole's `queries`
    table only indexes `timestamp` — there is no index on the client column,
    and this module must never modify Pi-hole's schema (read-only access is
    the whole point — see the module docstring). A per-client loop repeats
    the same ~650k-row timestamp-range scan once per client; measured ~6-7s
    total against the real Cube1 snapshot for ~19 clients, against a 5s
    dashboard poll interval. One batched query measures well under a second
    regardless of client count.
    """
    now = int(time.time())
    baseline_end = now - SILENT_WINDOW_HOURS * 3600
    baseline_start = now - BASELINE_DAYS * 86400
    recent_start_bucket = (baseline_end - baseline_start) // 3600
    total_hours = recent_start_bucket + SILENT_WINDOW_HOURS

    ccol = _client_ip_col()
    _, join = _client_join_sql()
    # `join` is a single JOIN against the small client-identity table (once,
    # as part of this one query's plan) — not the same cost as the per-client
    # WHERE-filtered scans this replaced. Still one pass over the
    # timestamp-indexed range regardless of client count.

    with _connect() as conn:
        bucket_rows = conn.execute(
            f"""
            SELECT {ccol} AS ip,
                   CAST((q.timestamp - ?) / 3600 AS INTEGER) AS bucket,
                   COUNT(*) AS n
            FROM queries q
            {join}
            WHERE q.timestamp >= ? AND q.timestamp <= ?
            GROUP BY ip, bucket
            """,
            [baseline_start, baseline_start, now],
        ).fetchall()
        # "First-seen" here deliberately means "earliest row within the
        # baseline window", NOT the client's true all-time first query — an
        # unwindowed full-table scan measured ~0.7s on its own against the
        # real Cube1 snapshot, and it turns out to be unnecessary: every use
        # below only ever compares this value against baseline_start/now, and
        # for both uses, a windowed earliest-row is functionally equivalent
        # to the true value clamped at baseline_start:
        #   - eligibility (`now - fs < 24h`) — a client active before the
        #     window has a windowed `fs` at/near baseline_start, which is
        #     always > 24h old, same conclusion as the true value.
        #   - clamping (`max(baseline_start, fs)`) — a client whose true
        #     first-ever query is within the window has a windowed `fs`
        #     equal to the true value (nothing before it was excluded); a
        #     client older than the window collapses to ≈baseline_start
        #     either way, which is exactly what the clamp resolves to anyway.
        # (One accepted edge case: a client active long ago, then fully
        # silent for over 7 days, then newly active again within the window
        # reads as "new" here instead of "returning" — reasonable, since it
        # has no useful recent baseline to compare against either way.)
        select, _ = _client_join_sql()
        first_seen_rows = conn.execute(
            f"""
            SELECT {select}, MIN(q.timestamp) AS fs
            FROM queries q
            {join}
            WHERE q.timestamp >= ?
            GROUP BY {ccol}
            """,
            [baseline_start],
        ).fetchall()

    first_seen = {r["client_ip"]: r["fs"] for r in first_seen_rows}
    names = {r["client_ip"]: (r["client_name"] or r["client_ip"]) for r in first_seen_rows}

    per_client_buckets: dict[str, dict[int, int]] = {}
    for r in bucket_rows:
        per_client_buckets.setdefault(r["ip"], {})[r["bucket"]] = r["n"]

    anomalies: list[dict] = []
    for ip, buckets in per_client_buckets.items():
        fs = first_seen.get(ip)
        if fs is None or (now - fs) < NEW_DEVICE_GRACE_SECONDS:
            continue  # too new to have a meaningful baseline

        # Clamp the baseline to the client's actual history so a client
        # between 24h and 7 days old doesn't get phantom pre-existence
        # zero-hours dragging its average down.
        effective_start_bucket = max(0, int((max(baseline_start, fs) - baseline_start) // 3600))
        baseline_series = [buckets.get(i, 0) for i in range(effective_start_bucket, recent_start_bucket)]
        if not baseline_series:
            continue
        avg = statistics.fmean(baseline_series)
        stddev = statistics.pstdev(baseline_series) if len(baseline_series) > 1 else 0.0

        # Same series covers both the silence check (all 3 hours zero) and
        # the spike check (current_value = the most recent of those 3 hours)
        # — so the two checks can never disagree about what "now" means.
        recent_series = [buckets.get(i, 0) for i in range(recent_start_bucket, total_hours)]
        current_value = recent_series[-1]
        name = names.get(ip, ip)

        if avg > SILENT_MIN_BASELINE_AVG and all(h == 0 for h in recent_series):
            anomalies.append({
                "ip": ip, "name": name, "kind": "silent",
                "baseline_avg": round(avg, 2), "baseline_stddev": round(stddev, 2),
                "current_value": 0,
                "window_since": baseline_end, "window_until": now,
            })
            continue

        threshold = avg + SPIKE_STDDEV_MULTIPLIER * stddev
        if current_value > threshold:
            anomalies.append({
                "ip": ip, "name": name, "kind": "spike",
                "baseline_avg": round(avg, 2), "baseline_stddev": round(stddev, 2),
                "current_value": current_value,
                "window_since": now - 3600, "window_until": now,
            })

    return anomalies


def health() -> dict:
    try:
        with _connect() as conn:
            conn.execute("SELECT 1 FROM queries LIMIT 1")
        return {"ok": True, "db_path": DB_PATH, "checked_at": int(time.time())}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "db_path": DB_PATH, "error": str(e)}
