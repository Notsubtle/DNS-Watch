"""
Incremental rollup cache for DNS Watch's "All"-time-range dashboard.

WHY THIS EXISTS
---------------
Bounded ranges (15m/1h/24h/7d) are already fast: they hit Pi-hole's own
`timestamp` index and scan only a small tail of the table. The "All" range is
the problem. At small-business / full-year scale (~40M rows) the whole-table
aggregates -- COUNT(DISTINCT domain), COUNT(DISTINCT client), multi-key
GROUP BYs -- have to scan and sort the ENTIRE table every time, measured at
13-32s. There is no index we could add to fix it: Pi-hole's FTL database is
read-only to us, permanently, by design (see db.py's module docstring).

The fix is to precompute those whole-table aggregates once and then maintain
them INCREMENTALLY: each refresh reads only the rows added since the last one
(a keyset cursor over `(timestamp, id)`, the same airtight compound cursor
tail_queries uses) and applies their deltas. It is deliberately NOT a
"recompute everything every N minutes" job -- a recurring full-table scan is
exactly the background-CPU pattern that caused visible system lag earlier in
this project's history, and was explicitly rejected.

WHERE THE STATE LIVES
---------------------
The rollup tables live in DNS Watch's OWN writable database
(`DNSWATCH_DB_PATH`, the same file alerts.py uses), never Pi-hole's FTL db,
which this process only ever opens read-only via db.py. Schema is created with
idempotent `CREATE TABLE IF NOT EXISTS`, matching alerts.init_store() -- this
codebase has no migration framework and doesn't need one here.

RESOLUTION / CORRECTNESS
------------------------
The rollup keys are RESOLVED TEXT (domain names, client ips), never raw
integer ids, so they are identical across every Pi-hole schema shape (the
older shapes have no integer ids at all). Resolution reuses db.py's existing,
already-tested helpers rather than reinventing them, so the two correctness
traps proven to matter in this codebase are handled the SAME way the trusted
aggregate paths handle them:

  * Duplicate-ip clients: client_by_id is not injective on ip (two ids can map
    to 127.0.0.1). Resolving via _resolve_client_value + _client_ip_map yields
    the same ip text for both ids, so they land in ONE rollup key and their
    counts sum -- exactly as the view groups by resolved ip.

  * Orphaned ids: a domain/client integer whose lookup row is missing resolves
    to None (via _resolve_domain_value / _resolve_client_value), matching the
    view's CASE-subquery yielding NULL. Such rows are EXCLUDED from the
    domain/client-keyed tables -- there is no domain/client to attribute the
    row to -- which mirrors summary()'s COUNT(DISTINCT ...) skipping NULLs.
    They are STILL counted in the type/day rollups, because a query with an
    unresolvable domain is still a real query with a known status and type;
    this is exactly summary()'s behavior, where total_queries counts every row
    but unique_domains/unique_clients exclude the NULL group. Keeping a literal
    NULL key instead would be both semantically wrong (it's not one domain) and
    mechanically broken (SQLite ON CONFLICT never dedupes NULL keys, so N
    orphan ids would fail to merge into one row).

SCOPE
-----
This module is ONLY the schema + the core incremental-update function. Wiring
it into the alert-eval tick, the one-time backfill, daily reconciliation, and
the dashboard read paths are separate, later tasks -- intentionally not here.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

from app import db

# Same physical database file as alerts.py's rule/event store. Defined here
# (rather than imported) so tests can monkeypatch this module's path in
# isolation; in production both resolve to the same DNSWATCH_DB_PATH file.
STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

# Rows processed per read+write transaction. Bounds memory and makes each
# committed batch a crash-safe checkpoint (the cursor advances in the SAME
# transaction as that batch's deltas -- see refresh_rollups).
DEFAULT_BATCH_SIZE = 5000

# Day bucketing is UTC. Deliberate: Pi-hole stores timestamps as epoch seconds
# and this rollup needs a single, config-free, stable day key. (client_heatmap
# uses the caller's local tz for its 7x24 grid, but that's a per-request view,
# not a persisted aggregate that must stay stable regardless of who's looking.)
def _day_str(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _connect() -> sqlite3.Connection:
    parent = os.path.dirname(STORE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(STORE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_rollup_store() -> None:
    """Create the rollup tables + the single-row cursor if absent.

    Idempotent, matching alerts.init_store(). The cursor row is seeded with
    NULLs meaning "nothing processed yet"; _read_cursor translates that to a
    sentinel that makes the first refresh process the whole table.
    """
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS domain_totals (
                domain TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS client_totals (
                ip TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER,
                last_seen INTEGER,
                name TEXT
            );
            CREATE TABLE IF NOT EXISTS query_type_totals (
                type INTEGER PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS daily_totals (
                day TEXT PRIMARY KEY,
                allowed_count INTEGER NOT NULL DEFAULT 0,
                blocked_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS client_domain_rollup (
                ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ip, domain)
            );
            CREATE TABLE IF NOT EXISTS client_activity_rollup (
                ip TEXT NOT NULL,
                day TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ip, day)
            );
            CREATE TABLE IF NOT EXISTS rollup_cursor (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_query_id INTEGER,
                last_query_timestamp REAL
            );
            INSERT OR IGNORE INTO rollup_cursor (id, last_query_id, last_query_timestamp)
                VALUES (1, NULL, NULL);
            """
        )
        conn.commit()


# Sentinel used when the cursor has never advanced. Real Pi-hole timestamps and
# ids are >= 0, so "> -1" (with the id tie-break) selects the whole table.
_CURSOR_START_TS = -1.0
_CURSOR_START_ID = -1


def _read_cursor(conn: sqlite3.Connection) -> tuple[float, int]:
    row = conn.execute(
        "SELECT last_query_id, last_query_timestamp FROM rollup_cursor WHERE id = 1"
    ).fetchone()
    if row is None or row["last_query_id"] is None:
        return _CURSOR_START_TS, _CURSOR_START_ID
    return float(row["last_query_timestamp"]), int(row["last_query_id"])


# --------------------------------------------------------------------------
# Reading new rows from Pi-hole (read-only), normalized to resolved text.
#
# _iter_new_rows yields dicts with the SAME shape regardless of Pi-hole schema:
#   {timestamp, id, domain (text|None), ip (text|None), name, type, status}
# so the accumulation/write code below is entirely schema-agnostic. domain/ip
# are None only for orphaned ids (idstore layout); older layouts store resolved
# text directly and never produce a None here.
# --------------------------------------------------------------------------


def _fetch_batch_idstore(
    conn: sqlite3.Connection, since_ts: float, since_id: int, limit: int
) -> list[dict]:
    """Normalized fast path: read raw `query_storage` columns and resolve
    domain/client through db.py's in-memory maps (no per-row correlated
    subquery). The maps are loaded per batch so a client/domain Pi-hole
    registered between batches is still resolvable rather than mis-seen as an
    orphan."""
    rows = conn.execute(
        """
        SELECT q.id AS id, q.timestamp AS timestamp, q.domain AS domain_raw,
               q.client AS client_raw, q.type AS type, q.status AS status
        FROM query_storage q
        WHERE (q.timestamp > ?) OR (q.timestamp = ? AND q.id > ?)
        ORDER BY q.timestamp ASC, q.id ASC
        LIMIT ?
        """,
        [since_ts, since_ts, since_id, limit],
    ).fetchall()
    if not rows:
        return []
    ipmap = db._client_ip_map(conn)
    namemap = db._client_name_map(conn)
    dmap = db._domain_text_map(conn)
    out = []
    for r in rows:
        ip = db._resolve_client_value(r["client_raw"], ipmap)
        out.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "domain": db._resolve_domain_value(r["domain_raw"], dmap),
            "ip": ip,
            "name": namemap.get(ip) if ip is not None else None,
            "type": r["type"],
            "status": r["status"],
        })
    return out


def _fetch_batch_view(
    conn: sqlite3.Connection, since_ts: float, since_id: int, limit: int
) -> list[dict]:
    """Older/other schemas: the `queries` view/table already exposes resolved
    domain text and client ip/name, so we read it directly via the same
    select+join the rest of db.py uses. These layouts have no integer ids,
    hence no orphan/duplicate-ip cases to handle here."""
    select, join = db._client_join_sql()
    rows = conn.execute(
        f"""
        SELECT q.id AS id, q.timestamp AS timestamp, q.domain AS domain,
               q.type AS type, q.status AS status, {select}
        FROM queries q
        {join}
        WHERE (q.timestamp > ?) OR (q.timestamp = ? AND q.id > ?)
        ORDER BY q.timestamp ASC, q.id ASC
        LIMIT ?
        """,
        [since_ts, since_ts, since_id, limit],
    ).fetchall()
    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "domain": r["domain"],
            "ip": r["client_ip"],
            "name": r["client_name"],
            "type": r["type"],
            "status": r["status"],
        }
        for r in rows
    ]


def _fetch_batch(
    conn: sqlite3.Connection, since_ts: float, since_id: int, limit: int
) -> list[dict]:
    if db.detect_schema().has_id_storage:
        return _fetch_batch_idstore(conn, since_ts, since_id, limit)
    return _fetch_batch_view(conn, since_ts, since_id, limit)


# --------------------------------------------------------------------------
# Accumulation + write
# --------------------------------------------------------------------------


class _Deltas:
    """In-memory deltas for ONE batch, keyed by resolved text, applied to the
    rollup tables in a single transaction."""

    def __init__(self) -> None:
        self.domain: dict[str, int] = {}
        self.client: dict[str, dict] = {}  # ip -> {count, first_seen, last_seen, name}
        self.qtype: dict[int, int] = {}
        self.daily: dict[str, list[int]] = {}  # day -> [allowed, blocked]
        self.client_domain: dict[tuple[str, str], int] = {}
        self.client_activity: dict[tuple[str, str], int] = {}

    def add(self, row: dict) -> None:
        ts = row["timestamp"]
        day = _day_str(ts)
        status = row["status"]
        domain = row["domain"]
        ip = row["ip"]

        # Type/day rollups count EVERY row -- they don't depend on resolving a
        # domain or client, so an orphaned-domain/client row still belongs here
        # (matching summary()'s total_queries counting every row).
        self.qtype[row["type"]] = self.qtype.get(row["type"], 0) + 1

        d = self.daily.setdefault(day, [0, 0])
        if status in db.BLOCKED_STATUSES:
            d[1] += 1
        elif status in db.ALLOWED_STATUSES:
            d[0] += 1
        # "unknown" status (neither set) is counted in neither column, matching
        # timeseries()'s allowed/blocked definitions.

        if domain is not None:
            self.domain[domain] = self.domain.get(domain, 0) + 1

        if ip is not None:
            ic = int(ts)
            c = self.client.get(ip)
            if c is None:
                self.client[ip] = {
                    "count": 1, "first_seen": ic, "last_seen": ic, "name": row["name"],
                }
            else:
                c["count"] += 1
                c["first_seen"] = min(c["first_seen"], ic)
                c["last_seen"] = max(c["last_seen"], ic)
                if row["name"] is not None:
                    c["name"] = row["name"]

            self.client_activity[(ip, day)] = self.client_activity.get((ip, day), 0) + 1
            if domain is not None:
                key = (ip, domain)
                self.client_domain[key] = self.client_domain.get(key, 0) + 1


def _apply(conn: sqlite3.Connection, deltas: _Deltas) -> None:
    """Apply one batch's deltas as UPSERT increments. Caller owns the
    transaction so the cursor update commits atomically with these writes."""
    if deltas.domain:
        conn.executemany(
            "INSERT INTO domain_totals (domain, count) VALUES (?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET count = count + excluded.count",
            list(deltas.domain.items()),
        )
    if deltas.qtype:
        conn.executemany(
            "INSERT INTO query_type_totals (type, count) VALUES (?, ?) "
            "ON CONFLICT(type) DO UPDATE SET count = count + excluded.count",
            list(deltas.qtype.items()),
        )
    if deltas.daily:
        conn.executemany(
            "INSERT INTO daily_totals (day, allowed_count, blocked_count) VALUES (?, ?, ?) "
            "ON CONFLICT(day) DO UPDATE SET "
            "allowed_count = allowed_count + excluded.allowed_count, "
            "blocked_count = blocked_count + excluded.blocked_count",
            [(day, a, b) for day, (a, b) in deltas.daily.items()],
        )
    if deltas.client:
        conn.executemany(
            "INSERT INTO client_totals (ip, count, first_seen, last_seen, name) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET "
            "count = count + excluded.count, "
            "first_seen = min(first_seen, excluded.first_seen), "
            "last_seen = max(last_seen, excluded.last_seen), "
            # Keep a known name rather than letting a later nameless row blank it.
            "name = COALESCE(excluded.name, client_totals.name)",
            [(ip, c["count"], c["first_seen"], c["last_seen"], c["name"])
             for ip, c in deltas.client.items()],
        )
    if deltas.client_domain:
        conn.executemany(
            "INSERT INTO client_domain_rollup (ip, domain, count) VALUES (?, ?, ?) "
            "ON CONFLICT(ip, domain) DO UPDATE SET count = count + excluded.count",
            [(ip, dom, n) for (ip, dom), n in deltas.client_domain.items()],
        )
    if deltas.client_activity:
        conn.executemany(
            "INSERT INTO client_activity_rollup (ip, day, count) VALUES (?, ?, ?) "
            "ON CONFLICT(ip, day) DO UPDATE SET count = count + excluded.count",
            [(ip, day, n) for (ip, day), n in deltas.client_activity.items()],
        )


def refresh_rollups(batch_size: int = DEFAULT_BATCH_SIZE) -> dict:
    """Bring the rollup tables up to date with everything added to Pi-hole
    since the cursor, then return {"processed": N, "batches": B}.

    Safe to call repeatedly. When nothing is new, the first keyset SELECT
    returns no rows (a cheap indexed range yielding nothing) and this is a
    no-op -- no wasted table scan. When there IS new data it is drained in
    `batch_size` chunks; each chunk is read from Pi-hole (read-only), its
    deltas accumulated, then written together with the cursor advance in ONE
    transaction on the writable store. Because the cursor moves in the same
    transaction as its batch's deltas, a crash mid-refresh rolls both back:
    rows are never double-counted (already-committed batches stay put and are
    not re-read) and never skipped (an uncommitted batch is retried from the
    old cursor).
    """
    init_rollup_store()
    processed = 0
    batches = 0
    # One read-only Pi-hole connection and one writable-store connection for the
    # whole drain. detect_schema() is cached, so the per-batch dispatch is free.
    read_conn = db._connect()
    try:
        with _connect() as write_conn:
            while True:
                since_ts, since_id = _read_cursor(write_conn)
                rows = _fetch_batch(read_conn, since_ts, since_id, batch_size)
                if not rows:
                    break
                deltas = _Deltas()
                for r in rows:
                    deltas.add(r)
                last = rows[-1]  # ordered ascending, so this is the new high-water mark
                write_conn.execute("BEGIN")
                _apply(write_conn, deltas)
                write_conn.execute(
                    "UPDATE rollup_cursor SET last_query_id = ?, last_query_timestamp = ? "
                    "WHERE id = 1",
                    [int(last["id"]), float(last["timestamp"])],
                )
                write_conn.commit()
                processed += len(rows)
                batches += 1
                if len(rows) < batch_size:
                    break
    finally:
        read_conn.close()
    return {"processed": processed, "batches": batches}
