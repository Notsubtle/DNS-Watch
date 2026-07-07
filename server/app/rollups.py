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

DRIFT / RECONCILIATION
----------------------
refresh_rollups only ever ADDS the deltas of rows newer than its cursor; it has
no signal for rows Pi-hole PRUNES on its own retention schedule (maxDBdays). So
over time the rollup totals drift upward relative to what's actually still in
Pi-hole's db -- an explicit, disclosed tradeoff: detecting/reversing individual
deletions would require the per-row history this rollup deliberately doesn't
keep. reconcile_rollups() corrects that drift by a rare (default: daily) full
rebuild from scratch, reusing the exact same incremental mechanism as the
initial backfill (see reconcile_rollups' own docstring for the safe-rebuild
design and why in-place truncate is correct here).

SCOPE
-----
This module is the rollup schema, the core incremental-update function, the
periodic full reconciliation, and (added later) the dashboard READ paths that
serve the unbounded "All" range straight off these precomputed tables. The read
functions live at the bottom of the file, under READ PATHS; db.py dispatches to
them for the `since is None` case and falls back to its direct scans otherwise.
"""

from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timezone

from app import db, names, resolve

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
                blocked_count INTEGER NOT NULL DEFAULT 0,
                unknown_count INTEGER NOT NULL DEFAULT 0
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
            -- Reconciliation clock, kept in its OWN single-row state table rather
            -- than as a column on rollup_cursor. The two have distinct lifetimes:
            -- reconcile_rollups REWINDS the cursor to NULL on every run, but the
            -- last-reconciled stamp must SURVIVE that rewind (it records when the
            -- last full rebuild finished, not what's been processed). Separating
            -- them keeps each table single-purpose, removes the footgun of a
            -- cursor reset accidentally clearing the clock, and needs no ALTER
            -- migration on stores created before this column existed -- it's a
            -- plain CREATE IF NOT EXISTS, matching this codebase's no-migration
            -- convention (alerts.init_store, and the cursor table above).
            CREATE TABLE IF NOT EXISTS rollup_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_reconciled_at REAL
            );
            INSERT OR IGNORE INTO rollup_meta (id, last_reconciled_at)
                VALUES (1, NULL);
            """
        )
        # daily_totals predates unknown_count (#2 -- needed so the "All" range's
        # timeseries total isn't silently undercounted by whatever fraction of
        # rows carry a status outside both BLOCKED_STATUSES/ALLOWED_STATUSES).
        # CREATE TABLE IF NOT EXISTS above is a no-op on a store that already has
        # the table, so a store created before this column existed needs an
        # explicit, idempotent ALTER -- this codebase's usual "just CREATE IF NOT
        # EXISTS" convention only covers whole new tables, not new columns on an
        # existing one.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(daily_totals)")}
        if "unknown_count" not in cols:
            conn.execute("ALTER TABLE daily_totals ADD COLUMN unknown_count INTEGER NOT NULL DEFAULT 0")
        conn.commit()


# Every table reconcile_rollups clears before a full rebuild. Module-level (not
# caller input) so it's safe to interpolate into the DELETE statements below.
_ROLLUP_TABLES = (
    "domain_totals",
    "client_totals",
    "query_type_totals",
    "daily_totals",
    "client_domain_rollup",
    "client_activity_rollup",
)


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
        self.daily: dict[str, list[int]] = {}  # day -> [allowed, blocked, unknown]
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

        d = self.daily.setdefault(day, [0, 0, 0])
        if status in db.BLOCKED_STATUSES:
            d[1] += 1
        elif status in db.ALLOWED_STATUSES:
            d[0] += 1
        else:
            # Tracked separately (#2) so read_timeseries()'s "total" can match
            # timeseries()'s COUNT(*) exactly -- allowed+blocked alone would
            # silently undercount by however many rows fall outside both sets
            # (real Pi-hole data: a status-14 "OTHER" tail was ~3% of all rows
            # in the snapshot this was validated against).
            d[2] += 1

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
            "INSERT INTO daily_totals (day, allowed_count, blocked_count, unknown_count) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(day) DO UPDATE SET "
            "allowed_count = allowed_count + excluded.allowed_count, "
            "blocked_count = blocked_count + excluded.blocked_count, "
            "unknown_count = unknown_count + excluded.unknown_count",
            [(day, a, b, u) for day, (a, b, u) in deltas.daily.items()],
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
            # A from-scratch drain (cursor still at the "nothing processed"
            # sentinel) happens in exactly two cases: true first boot, or
            # reconcile_rollups() rewinding the cursor before rebuilding. Either
            # way, once it fully completes that IS a fresh reconciliation by
            # definition -- see the stamp below, which fixes #3 (the redundant
            # double-backfill reconcile_rollups() would otherwise immediately
            # trigger on the same scheduler tick, since an unset stamp reads as
            # "never reconciled, do it now").
            started_ts, started_id = _read_cursor(write_conn)
            started_empty = started_ts == _CURSOR_START_TS and started_id == _CURSOR_START_ID

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

            if started_empty:
                write_conn.execute(
                    "UPDATE rollup_meta SET last_reconciled_at = ? WHERE id = 1",
                    [time.time()],
                )
                write_conn.commit()
    finally:
        read_conn.close()
    return {"processed": processed, "batches": batches}


def _read_last_reconciled(conn: sqlite3.Connection) -> float | None:
    row = conn.execute(
        "SELECT last_reconciled_at FROM rollup_meta WHERE id = 1"
    ).fetchone()
    if row is None or row["last_reconciled_at"] is None:
        return None
    return float(row["last_reconciled_at"])


def reconcile_rollups(interval_seconds: int = 86400, force: bool = False) -> dict:
    """Periodically rebuild the rollup tables from scratch to erase the upward
    drift refresh_rollups can't correct on its own (Pi-hole prunes old rows on
    its retention schedule; refresh only ever ADDS newer rows -- see the module
    docstring's DRIFT section).

    Gating: a no-op unless `force`, or at least `interval_seconds` have elapsed
    since the last successful reconciliation (an unset stamp == "never
    reconciled" == do it now). Cheap to call every scheduler tick -- the common
    path is a single indexed read of the meta row.

    SAFE-REBUILD DESIGN (in-place truncate, deliberately chosen over a
    temp-table swap):

      The rebuild clears all six rollup tables and rewinds the cursor to
      "nothing processed" in ONE transaction, then calls refresh_rollups() to
      re-drain the whole Pi-hole table via the exact same per-batch mechanism as
      the initial backfill. Two properties make this correct and crash-safe
      WITHOUT a swap:

        * Atomic reset. The truncate + cursor-rewind commit together, so a crash
          can never leave tables cleared but the cursor still advanced (which
          would silently skip rows on the next refresh) or vice-versa.

        * Self-healing rebuild. refresh_rollups advances the cursor in the SAME
          transaction as each batch's deltas. A crash mid-rebuild therefore
          leaves a consistent partial state that the NEXT refresh_rollups
          continues from and completes correctly -- totals are never permanently
          wrong. `last_reconciled_at` is stamped only AFTER the rebuild returns,
          so an interrupted run simply reconciles again next tick.

      A temp-table-into-atomic-swap design would additionally guarantee that a
      concurrent READER never observes the tables mid-rebuild (empty then
      climbing for the ~8s a full rebuild takes at real scale). That guarantee
      is deliberately NOT built here, for concrete structural reasons rather than
      to save effort:

        1. Nothing reads these tables yet -- the dashboard read path is a
           separate, later task -- so there is no reader to protect today.
        2. This store file is SHARED with alerts.py's rule/event/settings
           tables, so a whole-file swap (build a sibling db, os.replace it in) is
           out -- it would clobber unrelated state.
        3. A same-file shadow-table swap (build into `*_new` tables, RENAME them
           over the live ones in one txn) would force refresh_rollups to write to
           a configurable table namespace and cursor -- i.e. parameterizing the
           one component already verified at 764k-row scale -- for a benefit no
           current consumer can observe. The task's own constraint is to reuse
           refresh_rollups' batch/transaction logic verbatim, not fork it.

      The right time to add zero-window swap semantics is WHEN the read path is
      built, designed together with it (e.g. switch this store to WAL so a single
      long rebuild txn lets readers keep seeing the last committed snapshot, or
      add shadow tables and a read indirection as one unit). Pre-building that
      machinery now would be speculative complexity around the most
      correctness-sensitive code in the module. This deferral is intentional and
      flagged, not an oversight.
    """
    init_rollup_store()
    now = time.time()
    with _connect() as conn:
        last = _read_last_reconciled(conn)

    if not force and last is not None and (now - last) < interval_seconds:
        return {
            "reconciled": False,
            "last_reconciled_at": last,
            "seconds_until_due": interval_seconds - (now - last),
        }

    # Atomic reset: clear every rollup table AND rewind the cursor together, so
    # the "nothing processed" state is all-or-nothing (see docstring).
    with _connect() as conn:
        conn.execute("BEGIN")
        for table in _ROLLUP_TABLES:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608 — table names are module constants
        conn.execute(
            "UPDATE rollup_cursor SET last_query_id = NULL, last_query_timestamp = NULL "
            "WHERE id = 1"
        )
        conn.commit()

    # Rebuild from scratch using the SAME incremental drain as the initial
    # backfill -- not a reimplementation of it.
    result = refresh_rollups()

    # Stamp completion only after a fully successful rebuild, so an interrupted
    # run leaves the old stamp and reconciles again next tick.
    with _connect() as conn:
        conn.execute(
            "UPDATE rollup_meta SET last_reconciled_at = ? WHERE id = 1", [now]
        )
        conn.commit()

    return {
        "reconciled": True,
        "processed": result["processed"],
        "batches": result["batches"],
    }


# ==========================================================================
# READ PATHS
# --------------------------------------------------------------------------
# The dashboard's unbounded "All" range (db.py's functions called with
# since=None) is the ONLY case these serve -- bounded ranges are already fast
# on Pi-hole's own timestamp index and must never touch this cache (db.py's
# dispatch guarantees that; these functions are simply never called for a
# bounded range).
#
# Each read returns a result byte-for-byte equivalent to db.py's direct scan on
# the same data, OR None to signal "I can't serve this -- fall through to the
# direct path". None is returned in exactly one structural case: the rollup has
# never been backfilled (cursor still NULL), so its tables are empty for a
# reason UNRELATED to the real data. Serving zeros there would be wrong (not
# merely stale); the direct scan is correct-but-slow and is the right answer
# until the first scheduler tick backfills. Once the cursor has advanced even
# once, these tables are trusted as the (possibly up-to-one-tick-stale) truth --
# that lag is the deliberate design tradeoff, not an error (see module docstring).
#
# ORPHAN RECONSTRUCTION. domain_totals/client_totals key on RESOLVED text and
# EXCLUDE orphaned ids (an id with no lookup row) entirely -- there is no NULL
# key (SQLite ON CONFLICT can't dedupe NULL keys; see the module docstring's
# RESOLUTION section). But db.py's direct top_domains/top_clients DO emit a
# single collapsed {None: sum-of-all-orphan-rows} group (mirroring the view's
# one NULL group). That group is recovered here WITHOUT any schema change, from
# an invariant every refresh preserves: query_type_totals counts EVERY row
# exactly once, while domain_totals counts only rows whose domain resolved. Their
# difference is precisely the orphaned-domain row count -- the size of the None
# group. Same for clients (total rows minus resolved-client rows). This is plain
# arithmetic over existing columns, not a new rollup column.
# ==========================================================================


def _rollups_backfilled(conn: sqlite3.Connection) -> bool:
    """True once refresh_rollups has advanced the cursor at least once, i.e. the
    tables reflect real data rather than the empty just-created state. A NULL
    cursor means "never backfilled" -> the caller must fall through to the direct
    scan (empty rollups are not a valid answer, only a not-ready one)."""
    row = conn.execute(
        "SELECT last_query_id FROM rollup_cursor WHERE id = 1"
    ).fetchone()
    return row is not None and row["last_query_id"] is not None


def _total_rows(conn: sqlite3.Connection) -> int:
    """Every query the rollup has processed, counted once. query_type_totals is
    the right source: _Deltas.add increments it for EVERY row unconditionally
    (unlike domain/client totals, which skip orphans)."""
    return conn.execute(
        "SELECT COALESCE(SUM(count), 0) AS n FROM query_type_totals"
    ).fetchone()["n"]


def read_summary() -> dict | None:
    """Serve db.summary(None, None, None) -- the whole-db, no-client, no-until
    case -- entirely from the rollups. A client filter or any bound is NOT
    served here (client_totals has no per-client blocked/total breakdown, and a
    bound isn't the All range); db.py only calls this for the servable case.

    total_queries == SUM(query_type_totals) (every row). blocked ==
    SUM(daily_totals.blocked_count) (daily counts blocked independently of
    domain/client resolution, so orphan rows are included, matching the direct
    COUNT). unique_domains/unique_clients == the row counts of domain_totals/
    client_totals, which hold exactly the DISTINCT resolved domains/ips with
    orphans excluded -- identical to the direct path's COUNT(DISTINCT ...)
    skipping NULLs."""
    init_rollup_store()
    with _connect() as conn:
        if not _rollups_backfilled(conn):
            return None
        total = _total_rows(conn)
        blocked = conn.execute(
            "SELECT COALESCE(SUM(blocked_count), 0) AS n FROM daily_totals"
        ).fetchone()["n"]
        unique_domains = conn.execute(
            "SELECT COUNT(*) AS n FROM domain_totals"
        ).fetchone()["n"]
        unique_clients = conn.execute(
            "SELECT COUNT(*) AS n FROM client_totals"
        ).fetchone()["n"]
    return {
        "total_queries": total,
        "blocked": blocked,
        "blocked_pct": round((blocked / total) * 100, 1) if total else 0.0,
        "unique_clients": unique_clients,
        "unique_domains": unique_domains,
    }


def read_top_domains(client: str | None, limit: int) -> list[dict] | None:
    """Serve db.top_domains(client, None, limit).

    client is None -> rank domain_totals; the orphaned-domain rows across the
    whole db are recovered as one {domain: None} group (total rows minus resolved
    rows) and ranked alongside, exactly as the direct path folds all orphan ids
    into one NULL group.

    client is set -> rank that ip's rows from client_domain_rollup (built for
    precisely this per-client top-domains case); its orphan group is that ip's
    total rows (client_totals) minus its resolved-domain rows. An ip absent from
    client_totals has zero rows -> [] (same as the direct path's unknown ip)."""
    init_rollup_store()
    with _connect() as conn:
        if not _rollups_backfilled(conn):
            return None
        if client is None:
            rows = conn.execute(
                "SELECT domain, count FROM domain_totals"
            ).fetchall()
            resolved_sum = sum(r["count"] for r in rows)
            orphan_n = _total_rows(conn) - resolved_sum
        else:
            rows = conn.execute(
                "SELECT domain, count FROM client_domain_rollup WHERE ip = ?",
                [client],
            ).fetchall()
            crow = conn.execute(
                "SELECT count FROM client_totals WHERE ip = ?", [client]
            ).fetchone()
            client_total = crow["count"] if crow else 0
            resolved_sum = sum(r["count"] for r in rows)
            orphan_n = client_total - resolved_sum
    out = [{"domain": r["domain"], "count": r["count"]} for r in rows]
    if orphan_n > 0:
        out.append({"domain": None, "count": orphan_n})
    out.sort(key=lambda x: x["count"], reverse=True)
    return out[:limit]


def read_top_clients(limit: int) -> list[dict] | None:
    """Serve db.top_clients(None, limit) from client_totals. Each row is already
    one resolved ip (dup-ip ids merged at write time), so counts need no further
    merge. Orphaned-client rows -- excluded from client_totals -- are recovered
    as the single {ip: None, name: None} group the direct path emits (total rows
    minus resolved-client rows). name goes through the SAME precedence the direct
    path's _display_name applies -- manual override (names.py), else Pi-hole's
    own name (client_totals.name), else DNS Watch's reverse-DNS cache
    (resolve.py), else the bare ip -- rather than only ever falling back to the
    ip, so a manually-named or PTR-resolved client shows its friendly name on
    the All-time view exactly as it already does on every bounded range."""
    init_rollup_store()
    with _connect() as conn:
        if not _rollups_backfilled(conn):
            return None
        rows = conn.execute(
            "SELECT ip, count, name FROM client_totals"
        ).fetchall()
        orphan_n = _total_rows(conn) - sum(r["count"] for r in rows)
    resolved = resolve.get_names()
    manual = names.get_names()
    out = [
        {"ip": r["ip"], "name": db._display_name(r["name"], r["ip"], resolved, manual), "count": r["count"]}
        for r in rows
    ]
    if orphan_n > 0:
        # Orphaned clients collapse to one None-ip group with a None name, exactly
        # as the direct path's `namemap.get(None) or None` yields.
        out.append({"ip": None, "name": None, "count": orphan_n})
    out.sort(key=lambda x: x["count"], reverse=True)
    return out[:limit]


def read_query_types() -> list[dict] | None:
    """Serve db.query_types(None, None, None) from query_type_totals. `type` is a
    raw per-row column, so every row is counted under a resolvable type key --
    there is no orphan case here. Output shape and desc-by-count ordering match
    the direct path (ties, as in SQL's ORDER BY, are unordered among equals)."""
    init_rollup_store()
    with _connect() as conn:
        if not _rollups_backfilled(conn):
            return None
        rows = conn.execute(
            "SELECT type, count FROM query_type_totals"
        ).fetchall()
    out = [
        {"type_code": r["type"], "type": db.type_name(r["type"]), "count": r["count"]}
        for r in rows
    ]
    out.sort(key=lambda x: x["count"], reverse=True)
    return out


def _day_start_ts(day: str) -> int:
    """Inverse of _day_str: the UTC midnight timestamp a day key represents."""
    return int(datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp())


def _all_range_days(conn: sqlite3.Connection) -> list[str] | None:
    """Every UTC day key from the earliest day with data through today,
    inclusive, with no gaps -- the shared x-axis for read_timeseries() and
    read_client_activity() so the two "All" range charts always line up.
    `daily_totals` is the source of truth for "which days have any data" since
    _Deltas.add() writes a day bucket for EVERY row, including ones whose
    domain/client didn't resolve (unlike client_activity_rollup, which only
    gets a row when the client resolved) -- see the module's DRIFT note."""
    first = conn.execute("SELECT MIN(day) AS d FROM daily_totals").fetchone()["d"]
    if first is None:
        return None
    today = _day_str(time.time())
    days = []
    d = first
    while d <= today:
        days.append(d)
        d = _day_str(_day_start_ts(d) + 86400)
    return days


def read_timeseries() -> dict | None:
    """Serve db.timeseries(None, None, None, ...) -- the "All" range, no client
    filter -- from daily_totals, one bucket per UTC day (see #2: this trades
    the direct path's arbitrary data-window-derived bucket width for reusing
    the existing day-granular rollup as-is; a real, disclosed behavior change
    for this one chart, not a bug). "total" is allowed+blocked+unknown so it
    matches direct COUNT(*) exactly -- see unknown_count's own comment."""
    init_rollup_store()
    with _connect() as conn:
        if not _rollups_backfilled(conn):
            return None
        days = _all_range_days(conn)
        if days is None:
            return None
        rows = {
            r["day"]: r
            for r in conn.execute(
                "SELECT day, allowed_count, blocked_count, unknown_count FROM daily_totals"
            ).fetchall()
        }
    series = []
    for day in days:
        r = rows.get(day)
        allowed = r["allowed_count"] if r else 0
        blocked = r["blocked_count"] if r else 0
        unknown = r["unknown_count"] if r else 0
        series.append({
            "t": _day_start_ts(day),
            "allowed": allowed,
            "blocked": blocked,
            "total": allowed + blocked + unknown,
        })
    return {
        "since": series[0]["t"],
        "until": int(time.time()),
        "bucket_seconds": 86400,
        "series": series,
    }


def read_client_activity(limit: int) -> list[dict] | None:
    """Serve db.client_activity(None, None, limit, ...) -- the "All" range --
    from client_totals (top-N ranking + global first/last-seen, same source
    read_top_clients() uses) and client_activity_rollup (per-day sparkline).
    Same day-aligned bucketing tradeoff as read_timeseries() -- see #2."""
    init_rollup_store()
    with _connect() as conn:
        if not _rollups_backfilled(conn):
            return None
        days = _all_range_days(conn)
        if days is None:
            return None
        top = conn.execute(
            "SELECT ip, count, first_seen, last_seen, name FROM client_totals "
            "ORDER BY count DESC LIMIT ?",
            [limit],
        ).fetchall()
        if not top:
            return []
        ips = [t["ip"] for t in top]
        placeholders = ",".join("?" for _ in ips)
        spark_rows = conn.execute(
            f"SELECT ip, day, count FROM client_activity_rollup WHERE ip IN ({placeholders})",
            ips,
        ).fetchall()
    day_index = {day: i for i, day in enumerate(days)}
    spark_by_ip: dict[str, list[int]] = {ip: [0] * len(days) for ip in ips}
    for r in spark_rows:
        idx = day_index.get(r["day"])
        if idx is not None:  # guards a day outside the computed range, e.g. clock skew
            spark_by_ip[r["ip"]][idx] = r["count"]
    # Same name precedence as read_top_clients() / the direct path's
    # _display_name -- manual override, else Pi-hole's name, else the
    # reverse-DNS cache, else the bare ip.
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "ip": t["ip"],
            "name": db._display_name(t["name"], t["ip"], resolved, manual),
            "count": t["count"],
            "first_seen": t["first_seen"],
            "last_seen": t["last_seen"],
            "sparkline": spark_by_ip[t["ip"]],
        }
        for t in top
    ]
