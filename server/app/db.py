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

import regex as _timed_regex
from app import names, oui, psl, resolve
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DB_PATH = os.environ.get("PIHOLE_DB_PATH", "/pihole-data/pihole-FTL.db")

# dnsmasq's DHCP lease file (#58) -- lives alongside pihole-FTL.db in the same
# already-mounted, already read-only PIHOLE_ETC_PATH folder (see
# docker-compose.yml), so reading it needs no new privileges, no host
# networking -- just another file in a mount this app already has. Defaults
# to a sibling of DB_PATH rather than requiring a separate env var/compose
# change for the common case where both files share Pi-hole's etc folder.
LEASES_PATH = os.environ.get(
    "PIHOLE_DHCP_LEASES_PATH", os.path.join(os.path.dirname(DB_PATH), "dhcp.leases")
)

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
    # Newest FTL ("normalized") layout: `queries` is a VIEW over the real
    # `query_storage` table, and domain/client are stored as integer IDs
    # resolved through `domain_by_id`/`client_by_id`. When present, aggregate
    # queries can group/filter on the raw integer IDs directly instead of
    # paying the view's per-row correlated subquery. Purely additive: older
    # shapes (no query_storage) leave this False and behave exactly as before.
    has_id_storage: bool = False
    # Whether the `network` table exists and carries `hwaddr`/`macVendor`
    # columns (real Pi-hole v6 and the normalized "idstore" layout both have
    # this; the plain `client`-table schema has no `network` table at all, and
    # the oldest schema we support has a `network` table with only a bare
    # `name` column). Vendor enrichment (#4/#5) is a no-op when this is False.
    has_vendor_data: bool = False


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
        # The normalized fast path requires all three real tables to be present.
        # (`queries` itself is a VIEW in this layout; we detect the tables it
        # reads from, not the view.)
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        has_id_storage = {"query_storage", "domain_by_id", "client_by_id"}.issubset(tables)
        has_vendor_data = False
        if "network" in tables and "network_addresses" in tables:
            net_cols = {row["name"] for row in conn.execute("PRAGMA table_info(network)")}
            has_vendor_data = {"hwaddr", "macVendor"}.issubset(net_cols)
    return Schema(
        has_client_table=has_client_table,
        na_has_name=na_has_name,
        has_id_storage=has_id_storage,
        has_vendor_data=has_vendor_data,
    )


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


VALID_STATUS_FILTERS = {"all", "blocked", "allowed", "unknown"}


def _status_where(status: str | None) -> str | None:
    """SQL predicate (no params) restricting q.status to a resolved category.

    Returns None for "all"/None/anything unrecognized, so no status
    restriction is applied — matches prior behavior. Checked against an
    explicit allowlist (rather than an if/elif chain that happens to fall
    through safely today) as defense-in-depth: it stays impossible for a
    future refactor to string-format an unvalidated `status` value into the
    SQL text below, even though every branch here already builds its SQL
    from fixed int sets (BLOCKED_STATUSES/ALLOWED_STATUSES), never from
    `status` itself. Filtering in SQL (rather than post-filtering fetched
    rows in Python) is what lets LIMIT/OFFSET and COUNT(*) stay correct for
    status-filtered views.
    """
    if not status or status not in VALID_STATUS_FILTERS or status == "all":
        return None
    blocked = ",".join(str(s) for s in BLOCKED_STATUSES)
    allowed = ",".join(str(s) for s in ALLOWED_STATUSES)
    if status == "blocked":
        return f"q.status IN ({blocked})"
    if status == "allowed":
        return f"q.status IN ({allowed})"
    return f"q.status NOT IN ({blocked},{allowed})"  # "unknown"


def _build_where(
    client: str | list[str] | None = None,
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

    `client` is either a single ip (the original, single-device filter) or a
    list of ips (a tag/group's members — #31), so callers don't need two
    separate code paths. An empty list means "a real tag with no members" and
    correctly matches nothing, the same way a single unknown ip already
    matches nothing today.
    """
    where = ["1=1"]
    params: list = []
    if isinstance(client, (list, tuple, set)):
        client = list(client)
        if not client:
            where.append("0")
        else:
            placeholders = ",".join("?" for _ in client)
            where.append(f"{_client_ip_col()} IN ({placeholders})")
            params.extend(client)
    elif client:
        where.append(f"{_client_ip_col()} = ?")
        params.append(client)
    if domain:
        # Cap at the max valid DNS name length (253) before building the
        # LIKE pattern. A leading '%' already forces a full table scan; an
        # unbounded caller-supplied length on top of that is a cheap DoS
        # lever with no legitimate use (no real domain is longer than this).
        where.append("q.domain LIKE ?")
        params.append(f"%{domain[:253]}%")
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


# --------------------------------------------------------------------------
# Newer FTL ("normalized") fast path — see Schema.has_id_storage.
#
# In this layout `queries` is a VIEW over `query_storage`, and the view
# resolves the integer domain/client IDs to text with a CORRELATED SUBQUERY
# PER ROW (verified with EXPLAIN QUERY PLAN against a real snapshot). That is
# fine for the small, recently-paged reads (list_queries/tail) but is exactly
# what makes the whole-table AGGREGATES slow: they pay one subquery per
# scanned row just to build a GROUP BY key. The functions below instead
# GROUP/FILTER on the raw integer columns of `query_storage` and resolve
# names only for the handful of rows actually returned.
#
# Correctness invariants (each verified against the real UAT snapshot):
#   * domain_by_id.id is a PK and domain_by_id.domain is UNIQUE, so the
#     id<->text mapping is a bijection. Grouping by the integer domain id is
#     therefore identical to grouping by resolved text, including for
#     COUNT(DISTINCT domain).
#   * client_by_id is NOT injective on ip: two ids can map to the same ip
#     (127.0.0.1 appears as id 2 AND id 3 in the real snapshot). The trusted
#     view groups by *resolved ip*, so every client aggregate here groups by
#     raw id first and MERGES by resolved ip in Python. Client cardinality is
#     tiny (LAN devices), so this is cheap and exact.
#   * client NAME comes from network_addresses.name keyed by ip — the same
#     source the view-based path uses for this schema — not client_by_id.name.
# --------------------------------------------------------------------------


def _client_ids_for_ip(conn: sqlite3.Connection, ip: str) -> list[int]:
    """Every client_by_id.id whose ip matches `ip` (usually one, but the ip
    column is not unique — see module note above)."""
    return [r["id"] for r in conn.execute("SELECT id FROM client_by_id WHERE ip = ?", [ip])]


def _client_ids_for_client_filter(
    conn: sqlite3.Connection, client: str | list[str] | None
) -> list[int] | None:
    """Resolves an aggregate function's `client` filter (a single ip, a list
    of ips from a tag/group — #31, or None for "no filter") into the flat
    list of client_by_id ids `_id_where` expects. None passes through
    unchanged (no filter at all); a real but empty list (a tag with no
    members) correctly returns an empty list, which `_id_where` already
    treats as "match nothing" rather than "no filter"."""
    if isinstance(client, (list, tuple, set)):
        ips = list(client)
        if not ips:
            return []
        placeholders = ",".join("?" for _ in ips)
        return [
            r["id"]
            for r in conn.execute(f"SELECT id FROM client_by_id WHERE ip IN ({placeholders})", ips)
        ]
    # A single ip, matching _build_where's own `if client:` falsy check --
    # None or an empty string both mean "no filter", not "filter to nothing".
    if not client:
        return None
    return _client_ids_for_ip(conn, client)


def _client_ip_map(conn: sqlite3.Connection) -> dict[int, str]:
    return {r["id"]: r["ip"] for r in conn.execute("SELECT id, ip FROM client_by_id")}


def _ids_for_ips(ipmap: dict[int, str], ips) -> list[int]:
    """All client_by_id ids whose resolved ip is in `ips` (inverse of ipmap).
    Used to translate a set of resolved ips back to every raw id that maps to
    them, so a WHERE filter over query_storage covers all of a client's ids."""
    wanted = set(ips)
    return [cid for cid, ip in ipmap.items() if ip in wanted]


def _client_name_map(conn: sqlite3.Connection) -> dict[str, str | None]:
    """ip -> name, from network_addresses (the same source _client_join_sql's
    na_has_name branch reads). ips absent here resolve to None, matching the
    view path's LEFT JOIN."""
    return {r["ip"]: r["name"] for r in conn.execute("SELECT ip, name FROM network_addresses")}


def clients_missing_name(limit: int = 50) -> list[str]:
    """Client IPs Pi-hole has never named, most recently active first — the
    candidate list resolve.py's background PTR pass works through. Capped so
    a LAN with many silent/unnamed devices can't turn one scheduler tick into
    an unbounded scan."""
    if detect_schema().has_id_storage:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT q.client AS cid, MAX(q.timestamp) AS last_seen "
                "FROM query_storage q GROUP BY q.client"
            ).fetchall()
            ipmap = _client_ip_map(conn)
            namemap = _client_name_map(conn)
        merged: dict[str, float] = {}
        for r in rows:
            ip = _resolve_client_value(r["cid"], ipmap)
            merged[ip] = max(merged.get(ip, 0), r["last_seen"])
        missing = [ip for ip in merged if not namemap.get(ip)]
        missing.sort(key=lambda ip: merged[ip], reverse=True)
        return missing[:limit]

    select, join = _client_join_sql()
    sql = f"""
        SELECT {select}, MAX(q.timestamp) AS last_seen
        FROM queries q
        {join}
        GROUP BY {_client_ip_col()}
        HAVING client_name IS NULL OR client_name = ''
        ORDER BY last_seen DESC
        LIMIT ?
    """
    with _connect() as conn:
        rows = conn.execute(sql, [limit]).fetchall()
    return [r["client_ip"] for r in rows]


def _display_name(
    client_name: str | None, ip: str, resolved: dict[str, str], manual: dict[str, str]
) -> str:
    """The user's own manual override (names.py) always wins — it's a deliberate
    human decision, not another guess to arbitrate against Pi-hole's. Below that:
    Pi-hole's own name, else DNS Watch's own reverse-DNS cache (resolve.py), else
    the bare IP — the same "never blank, never lie about what we know" fallback
    every client-name field in this module already used before resolve.py/
    names.py existed, just with two more rungs added below Pi-hole's name."""
    return manual.get(ip) or client_name or resolved.get(ip) or ip


def is_placeholder_hwaddr(hwaddr: str | None) -> bool:
    """True when Pi-hole never captured a real layer-2 address for this client.

    Pi-hole falls back to a synthetic `ip-<addr>` value in `network.hwaddr`
    whenever it has no observed MAC for a client (cross-subnet/VLAN traffic,
    an expired DHCP lease record, a gap after a Pi-hole restart, ...) — see
    issue #4/#7. Callers use this to distinguish "we know the vendor is
    unknown" from "we can't know the vendor at all for this client"."""
    return not hwaddr or hwaddr.startswith("ip-")


def _client_vendor_map(conn: sqlite3.Connection) -> dict[str, dict]:
    """ip -> {"hwaddr", "mac_known", "vendor", "vendor_unknown_reason"}, from
    `network`/`network_addresses`, with an offline OUI-table fallback (#5)
    when Pi-hole's own `macVendor` is empty.

    Independent of `_client_join_sql()`'s name-only join: real Pi-hole v6
    (`na_has_name=True`) never joins `network` there, since the name lives on
    `network_addresses.name`. Vendor data (hwaddr/macVendor) only lives on
    `network`, so it needs its own join through `network_addresses.network_id`.
    Returns {} entirely when `has_vendor_data` is False (schema has no
    `network` table, or one without hwaddr/macVendor columns)."""
    if not detect_schema().has_vendor_data:
        return {}
    rows = conn.execute(
        "SELECT na.ip AS ip, n.hwaddr AS hwaddr, n.macVendor AS vendor "
        "FROM network_addresses na JOIN network n ON n.id = na.network_id"
    ).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        mac_known = not is_placeholder_hwaddr(r["hwaddr"])
        hwaddr = r["hwaddr"] if mac_known else None
        vendor = (r["vendor"] or None) if mac_known else None
        reason = None
        if mac_known and not vendor:
            # Pi-hole didn't resolve a vendor itself — try our own offline
            # MA-L lookup before giving up. A locally-administered (randomized)
            # MAC has no vendor in ANY registry by design, so label that
            # distinctly from "real MAC, genuinely not in our table".
            if oui.is_locally_administered(hwaddr):
                reason = "randomized"
            else:
                vendor = oui.lookup_vendor(hwaddr)
                reason = None if vendor else "unlisted"
        out[r["ip"]] = {
            "hwaddr": hwaddr,
            "mac_known": mac_known,
            "vendor": vendor,
            "vendor_unknown_reason": reason,
        }
    return out


def _vendor_fields(ip: str, vmap: dict[str, dict]) -> dict:
    """Default vendor fields for a client absent from vmap (no vendor row at
    all — e.g. a `client`-table schema, or a client Pi-hole's `network` table
    never recorded)."""
    return vmap.get(
        ip,
        {"hwaddr": None, "mac_known": False, "vendor": None, "vendor_unknown_reason": None},
    )


def list_vendors() -> list[dict]:
    """Every distinct RESOLVED vendor string currently on record, each with
    its member ips, for the dashboard's vendor filter (#11 remaining scope).

    Deliberately scoped to clients with an actual resolved vendor name --
    unlike a tag, "vendor" isn't a stored/nameable entity a user creates, so
    there's no sensible group for "unknown vendor"/"private MAC" clients to
    join here (that grouping already exists as informational text elsewhere,
    e.g. DeviceNamesModal, not as a filterable scope). Returns [] entirely
    when this schema carries no vendor data at all (has_vendor_data=False)."""
    with _connect() as conn:
        vmap = _client_vendor_map(conn)
    by_vendor: dict[str, list[str]] = {}
    for ip, v in vmap.items():
        vendor = v.get("vendor")
        if vendor:
            by_vendor.setdefault(vendor, []).append(ip)
    return [
        {"name": vendor, "ips": sorted(ips)}
        for vendor, ips in sorted(by_vendor.items())
    ]


def client_ips_for_vendor(vendor: str) -> list[str]:
    """Every client ip whose resolved vendor exactly matches `vendor`, for the
    dashboard's vendor filter/alert-rule scoping (#11 remaining scope).

    Unlike tags.get_tag_ips, there's no "unknown vendor name" case to signal
    with None -- vendor isn't a stored entity a user creates, it's a live,
    derived grouping over whatever clients currently resolve to that string.
    A typo'd or since-vanished vendor name simply matches no clients, the
    same silent-empty behaviour an unrecognized single ip filter already has
    in _build_where."""
    with _connect() as conn:
        vmap = _client_vendor_map(conn)
    return sorted(ip for ip, v in vmap.items() if v.get("vendor") == vendor)


def _domain_text_map(conn: sqlite3.Connection) -> dict[int, str]:
    """id -> domain text, from domain_by_id. domain_by_id.id is a PK and
    domain_by_id.domain is UNIQUE, so this is a bijection (see the module note
    on the normalized fast path). The inverse of the view's per-row lookup,
    materialized once so a batch of rows can be resolved without the correlated
    subquery."""
    return {r["id"]: r["domain"] for r in conn.execute("SELECT id, domain FROM domain_by_id")}


def _resolve_domain_value(dom, dmap: dict[int, str]):
    """Mirror the view's `CASE typeof(domain) WHEN 'integer' THEN <lookup>
    ELSE domain END` for domains, the exact analogue of _resolve_client_value:
    an integer id resolves through domain_by_id's text map (None if the id is
    ORPHANED -- absent from domain_by_id -- exactly as the view's subquery
    yields NULL for it); a value already stored as text resolves to itself.
    Callers that group/dedupe on the result therefore treat every orphaned id
    as the same None bucket, matching the view's single NULL group."""
    if isinstance(dom, int):
        return dmap.get(dom)
    return dom


def _resolve_client_value(cid, ipmap: dict[int, str]):
    """Mirror the view's `CASE typeof(client) WHEN 'integer' THEN <lookup>
    ELSE client END`: an integer id resolves through client_by_id's ip map
    (None if the id is ORPHANED -- absent from client_by_id -- exactly as the
    view's subquery yields NULL for it); a value already stored as text
    resolves to itself. Callers that group/dedupe on the result therefore treat
    every orphaned id as the same None bucket, matching the view's single NULL
    group."""
    if isinstance(cid, int):
        return ipmap.get(cid)
    return cid


def _id_where(
    client_ids: list[int] | None = None,
    since: int | None = None,
    until: int | None = None,
    status: str | None = None,
) -> tuple[str, list]:
    """WHERE builder for the raw `query_storage` table (aliased `q`).

    Mirrors _build_where's semantics for the filters the rewritten aggregates
    actually use (client, since, until, status). `client_ids` is the set of
    client_by_id ids for a requested ip (may be several — see module note);
    an empty list means "ip matched no known client" and yields no rows, the
    same result the view path gives for `q.client = <unknown ip>`.
    """
    where = ["1=1"]
    params: list = []
    if client_ids is not None:
        if not client_ids:
            where.append("0")  # unknown ip -> match nothing
        else:
            ph = ",".join("?" for _ in client_ids)
            where.append(f"q.client IN ({ph})")
            params.extend(client_ids)
    if since:
        where.append("q.timestamp >= ?")
        params.append(since)
    if until:
        where.append("q.timestamp <= ?")
        params.append(until)
    status_pred = _status_where(status)  # builds `q.status IN (...)` from fixed int sets
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
        vmap = _client_vendor_map(conn)
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "ip": r["client_ip"],
            "name": _display_name(r["client_name"], r["client_ip"], resolved, manual),
            "query_count": r["query_count"],
            **_vendor_fields(r["client_ip"], vmap),
        }
        for r in rows
    ]


def device_name_rows() -> list[dict]:
    """Every name source broken out separately (not just db._display_name's
    final pick) for the "Manage Device Names" UI — a user renaming a device
    needs to see what Pi-hole/rDNS already call it, not just the winner.

    Includes ips with a manual name but no CURRENT Pi-hole traffic (a device
    that's gone quiet or been replaced) so a stale override stays visible and
    deletable in the UI instead of silently vanishing — `seen` distinguishes
    the two cases."""
    select, join = _client_join_sql()
    sql = f"""
        SELECT {select}, COUNT(*) AS query_count, MAX(q.timestamp) AS last_seen
        FROM queries q
        {join}
        GROUP BY {_client_ip_col()}
        ORDER BY query_count DESC
    """
    with _connect() as conn:
        rows = conn.execute(sql).fetchall()
        vmap = _client_vendor_map(conn)
    resolved = resolve.get_names()
    manual = names.get_names()

    out = []
    seen_ips = set()
    for r in rows:
        ip = r["client_ip"]
        seen_ips.add(ip)
        out.append({
            "ip": ip,
            "manual_name": manual.get(ip),
            "pihole_name": r["client_name"],
            "resolved_name": resolved.get(ip),
            "display_name": _display_name(r["client_name"], ip, resolved, manual),
            "query_count": r["query_count"],
            "last_seen": r["last_seen"],
            "seen": True,
            **_vendor_fields(ip, vmap),
        })

    for ip, manual_name in manual.items():
        if ip in seen_ips:
            continue
        out.append({
            "ip": ip,
            "manual_name": manual_name,
            "pihole_name": None,
            "resolved_name": resolved.get(ip),
            "display_name": manual_name,
            "query_count": 0,
            "last_seen": None,
            "seen": False,
            **_vendor_fields(ip, {}),
        })
    return out


def list_queries(
    client: str | list[str] | None,
    domain: str | None,
    status: str | None,
    since: int | None,
    until: int | None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    # Bounded here (not just at the HTTP layer in main.py) so any other
    # caller of this function directly — a future script, a rule, a test —
    # can't materialize an unbounded result set via fetchall().
    limit = max(1, min(limit, 100_000))
    offset = max(0, min(offset, 10_000_000))

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

    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "timestamp": r["timestamp"],
            "domain": r["domain"],
            "query_type": r["type"],
            "raw_status": r["status"],
            "status": r["resolved_status"],
            "client_ip": r["client_ip"],
            "client_name": _display_name(r["client_name"], r["client_ip"], resolved, manual),
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
    limit = max(1, min(limit, 2000))  # bounded here too — see list_queries()
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
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "domain": r["domain"],
            "query_type": r["type"],
            "raw_status": r["status"],
            "status": r["resolved_status"],
            "client_ip": r["client_ip"],
            "client_name": _display_name(r["client_name"], r["client_ip"], resolved, manual),
        }
        for r in rows
    ]


def count_queries(
    client: str | list[str] | None,
    domain: str | None,
    status: str | None,
    since: int | None,
    until: int | None,
) -> int:
    """Total rows matching the same filters as list_queries, ignoring paging.

    Lets the frontend show "showing 200 of 5,000" and build pager controls.
    """
    if detect_schema().has_id_storage:
        return _count_queries_id(client, domain, status, since, until)
    _, join = _client_join_sql()
    where_sql, params = _build_where(client, domain, status, since, until)
    sql = f"SELECT COUNT(*) AS n FROM queries q {join} WHERE {where_sql}"
    with _connect() as conn:
        return conn.execute(sql, params).fetchone()["n"]


def _count_queries_id(
    client: str | list[str] | None,
    domain: str | None,
    status: str | None,
    since: int | None,
    until: int | None,
) -> int:
    """count_queries fast path for the normalized (has_id_storage) schema (#9).

    A plain COUNT(*) against the `queries` view was paying the view's per-row
    CORRELATED SCALAR SUBQUERY that resolves the client id to a name -- work
    whose result a count never uses. Counting query_storage directly instead
    lets a bounded, unfiltered range resolve entirely from the timestamp index
    (SEARCH ... USING COVERING INDEX idx_queries_timestamp, verified with
    EXPLAIN QUERY PLAN against the real UAT snapshot: ~37ms vs. ~320ms for a
    684k-row 7-day window -- no row materialization at all).

    Domain filtering resolves matching ids from domain_by_id once (a small,
    distinct-domains table) rather than resolving id->text per query_storage
    row. Like the existing client-id filter in _id_where, this only matches
    rows stored as an integer id (every row in the current schema data is),
    not the view's fallback for a literal-text domain/client value -- the
    same simplification every other id-based aggregate in this module already
    makes.
    """
    with _connect() as conn:
        client_ids = _client_ids_for_client_filter(conn, client)
        where_sql, params = _id_where(client_ids, since, until, status)
        if domain:
            where_sql += " AND q.domain IN (SELECT id FROM domain_by_id WHERE domain LIKE ?)"
            params.append(f"%{domain[:253]}%")
        sql = f"SELECT COUNT(*) AS n FROM query_storage q WHERE {where_sql}"
        return conn.execute(sql, params).fetchone()["n"]


def summary(client: str | list[str] | None, since: int | None, until: int | None) -> dict:
    # Unbounded whole-db summary is precomputed in the rollup cache. A client
    # filter or any bound is NOT servable from it (no per-client breakdown; a
    # bound isn't the "All" range) -- those fall straight through unchanged.
    if client is None and since is None and until is None:
        from app import rollups
        served = rollups.read_summary()
        if served is not None:
            return served
    if detect_schema().has_id_storage:
        return _summary_id(client, since, until)
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


def _summary_id(client: str | list[str] | None, since: int | None, until: int | None) -> dict:
    """Fast path for summary. total/blocked/unique_domains come from a single
    subquery-free scan of query_storage's raw columns. unique_domains counts
    DISTINCT resolved domains, matching the view's COUNT(DISTINCT domain): the
    LEFT JOIN to domain_by_id yields d.id == q.domain for a resolvable id
    (bijection, so distinct ids == distinct texts) and NULL for an ORPHANED id
    -- one whose row is missing from domain_by_id -- which COUNT(DISTINCT ...)
    then skips, exactly as the view resolves an orphan to NULL and skips it.
    Grouping on the raw id alone would instead count every orphaned id as its
    own "distinct domain", overcounting. The join is a single indexed PK seek
    per row, not the view's per-column correlated subquery. unique_clients
    CANNOT use COUNT(DISTINCT client) on the raw id -- two ids can share one ip
    -- so the distinct client ids are fetched (a tiny set) and de-duplicated by
    resolved ip in Python; unresolved/orphaned client ids resolve to None and
    are excluded, matching the view's COUNT(DISTINCT resolved_ip) skipping
    NULLs."""
    blocked_in = ",".join(str(s) for s in BLOCKED_STATUSES)
    with _connect() as conn:
        client_ids = _client_ids_for_client_filter(conn, client)
        where_sql, params = _id_where(client_ids=client_ids, since=since, until=until)
        r = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN q.status IN ({blocked_in}) THEN 1 ELSE 0 END) AS blocked,
                COUNT(DISTINCT d.id) AS unique_domains
            FROM query_storage q
            LEFT JOIN domain_by_id d ON d.id = q.domain
            WHERE {where_sql}
            """,
            params,
        ).fetchone()
        distinct_cids = conn.execute(
            f"SELECT DISTINCT q.client AS cid FROM query_storage q WHERE {where_sql}",
            params,
        ).fetchall()
        ipmap = _client_ip_map(conn)

    total = r["total"] or 0
    blocked = r["blocked"] or 0
    unique_clients = len(
        {_resolve_client_value(row["cid"], ipmap) for row in distinct_cids} - {None}
    )
    return {
        "total_queries": total,
        "blocked": blocked,
        "blocked_pct": round((blocked / total) * 100, 1) if total else 0.0,
        "unique_clients": unique_clients,
        "unique_domains": r["unique_domains"] or 0,
    }


def top_domains(client: str | list[str] | None, since: int | None, limit: int = 15) -> list[dict]:
    # Unbounded: served from domain_totals (client is None) or client_domain_rollup
    # (a single client set) -- both cover the "All" range. A tag/group (client is
    # a list -- #31) has no per-tag rollup table, so that falls through to the
    # direct scan just like a bound does; only None or one plain ip can use this
    # rollup path.
    if since is None and not isinstance(client, (list, tuple, set)):
        from app import rollups
        served = rollups.read_top_domains(client, limit)
        if served is not None:
            return served
    if detect_schema().has_id_storage:
        return _top_domains_id(client, since, limit)
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


def _top_domains_id(client: str | list[str] | None, since: int | None, limit: int) -> list[dict]:
    """Fast path: GROUP BY the raw integer domain id on query_storage. Resolvable
    ids are a bijection with their text (domain_by_id.domain is UNIQUE), so each
    is its own group and never merges with another -- the INNER JOIN yields the
    resolved text directly and the top `limit` fall straight out of SQL.

    ORPHANED ids -- referenced by query_storage but absent from domain_by_id --
    are the exception: the view resolves EVERY orphan to NULL, so they all
    collapse into a SINGLE NULL group whose count is the sum across all orphaned
    ids. Grouping on the raw id can't see that (each orphan id is a distinct
    integer, hence a distinct group), and an orphan that is individually below
    the top-N cut can still belong in the result once summed -- so a naive
    "overfetch a margin then merge" is not safe here. Instead the orphan rows
    are counted as one group directly in SQL (LEFT JOIN ... WHERE d.id IS NULL),
    then folded in as a single {domain: None} entry before the final sort/limit,
    reproducing the view's single-NULL-group semantics exactly."""
    with _connect() as conn:
        client_ids = _client_ids_for_client_filter(conn, client)
        where_sql, params = _id_where(client_ids=client_ids, since=since)
        # Non-orphan domains: bijection, so raw-id groups == resolved-text groups.
        # LIMIT here is safe -- at most `limit` of these can survive the final cut,
        # even after the single orphan group is added below.
        rows = conn.execute(
            f"""
            SELECT d.domain AS domain, COUNT(*) AS n
            FROM query_storage q
            JOIN domain_by_id d ON d.id = q.domain
            WHERE {where_sql}
            GROUP BY q.domain
            ORDER BY n DESC
            LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
        # Every orphaned domain id, summed into one NULL group (the view's shape).
        orphan_n = conn.execute(
            f"""
            SELECT COUNT(*) AS n
            FROM query_storage q
            LEFT JOIN domain_by_id d ON d.id = q.domain
            WHERE {where_sql} AND d.id IS NULL AND typeof(q.domain) = 'integer'
            """,
            params,
        ).fetchone()["n"]

    out = [{"domain": r["domain"], "count": r["n"]} for r in rows]
    if orphan_n:
        out.append({"domain": None, "count": orphan_n})
    out.sort(key=lambda x: x["count"], reverse=True)
    return out[:limit]


# --------------------------------------------------------------------------
# Domain lexical/entropy scoring (#3 in the feature backlog): a SOFT,
# per-domain metric complementing the NXDOMAIN-rate anomaly detector -- a
# live C2/DGA domain that actually resolves won't trip NXDOMAIN detection at
# all (it only fires on failed lookups), but a high-entropy/algorithmically-
# generated label scores high here regardless of whether it resolves.
#
# Deliberately presented as a soft score/badge everywhere it's surfaced,
# NEVER a hard alert -- legitimately random-looking hostnames (CDN edge
# nodes, content hashes, hashed asset paths) are common and would make a
# hard threshold noisy on an ordinary home network.
# --------------------------------------------------------------------------

# Below this many characters, entropy is too noisy to mean anything (e.g. a
# 4-character label has at most 2 bits/char of headroom just from being
# short) -- short domains are never flagged regardless of their score.
DOMAIN_ENTROPY_MIN_LENGTH = 8
# Shannon entropy, bits/char, over the label(s) sitting in front of the
# registered parent domain. English words/hostnames typically land under
# ~3.0; random/base32-ish DGA output typically lands well above it. Chosen
# as a conventional DGA-detection cutoff, not tuned against this app's own
# data -- see the module note above on why this is a soft score, not a hard
# alert threshold.
DOMAIN_ENTROPY_THRESHOLD = 3.3


def _shannon_entropy(s: str) -> float:
    """Bits per character, over `s`'s own character frequency distribution.
    0.0 for an empty or single-repeated-character string (no information)."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def domain_entropy(domain: str | None) -> float:
    """Entropy of the part of `domain` that sits IN FRONT OF its registered
    parent (see app/psl.py) -- e.g. for "a1b2c3.tunnel.example.com" this
    scores "a1b2c3.tunnel", not the whole hostname, so a domain's popularity
    or a long-but-ordinary registered name (github.io) doesn't dilute the
    score of whatever a client actually chose to put in front of it. Falls
    back to the whole hostname when there's nothing in front of the parent
    (domain.registered_domain(domain) == domain itself)."""
    if not domain:
        return 0.0
    parent = psl.registered_domain(domain)
    prefix = domain[: -len(parent) - 1] if len(domain) > len(parent) else domain
    return _shannon_entropy(prefix.replace(".", ""))


def is_high_entropy_domain(domain: str | None) -> bool:
    if not domain or len(domain) < DOMAIN_ENTROPY_MIN_LENGTH:
        return False
    return domain_entropy(domain) >= DOMAIN_ENTROPY_THRESHOLD


def client_entropy_summary(ip: str, since: int | None = None, limit_domains: int = 500) -> dict:
    """Per-client "% of this device's distinct domains that look
    high-entropy" (#3) -- computed over DISTINCT domains (via top_domains),
    not raw query volume, so a client hammering one high-entropy domain
    doesn't dominate the percentage the way a query-count-weighted average
    would."""
    domains = top_domains(ip, since, limit=limit_domains)
    named = [d["domain"] for d in domains if d["domain"] is not None]
    high = [d for d in named if is_high_entropy_domain(d)]
    total = len(named)
    return {
        "total_domains": total,
        "high_entropy_count": len(high),
        "pct_high_entropy": round(100 * len(high) / total, 1) if total else 0.0,
        "sample_domains": high[:10],
    }


def top_blocked_per_client(
    client: str | list[str] | None, since: int | None, limit: int = 15
) -> list[dict]:
    """Rank blocked (client, domain) pairs in the current dashboard scope."""
    if detect_schema().has_id_storage:
        return _top_blocked_per_client_id(client, since, limit)

    select, join = _client_join_sql()
    where_sql, params = _build_where(client=client, status="blocked", since=since)
    sql = f"""
        SELECT {select}, q.domain, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE {where_sql}
        GROUP BY {_client_ip_col()}, q.domain
        ORDER BY n DESC
        LIMIT ?
    """
    with _connect() as conn:
        rows = conn.execute(sql, [*params, limit]).fetchall()
    return [
        {
            "client_ip": r["client_ip"],
            "client_name": r["client_name"],
            "domain": r["domain"],
            "blocked_count": r["n"],
        }
        for r in rows
    ]


def _top_blocked_per_client_id(
    client: str | list[str] | None, since: int | None, limit: int
) -> list[dict]:
    """Fast path for normalized storage.

    Grouping starts on raw ids to avoid the queries view's per-row subqueries,
    then merges by resolved (client_ip, domain). The merge must happen before
    LIMIT because client ids are not unique by ip, and orphaned integer domain
    ids all resolve to the view's single NULL domain group.
    """
    with _connect() as conn:
        client_ids = _client_ids_for_client_filter(conn, client)
        where_sql, params = _id_where(client_ids=client_ids, since=since, status="blocked")
        rows = conn.execute(
            f"""
            SELECT q.client AS cid,
                   CASE typeof(q.domain)
                       WHEN 'integer' THEN d.domain
                       ELSE q.domain
                   END AS domain,
                   COUNT(*) AS n
            FROM query_storage q
            LEFT JOIN domain_by_id d ON d.id = q.domain
            WHERE {where_sql}
            GROUP BY q.client, q.domain
            """,
            params,
        ).fetchall()
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)

    merged: dict[tuple[str | None, str | None], int] = {}
    for r in rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        key = (ip, r["domain"])
        merged[key] = merged.get(key, 0) + r["n"]

    ordered = sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [
        {
            "client_ip": ip,
            "client_name": namemap.get(ip),
            "domain": domain,
            "blocked_count": n,
        }
        for (ip, domain), n in ordered
    ]


def top_clients(since: int | None, limit: int = 15) -> list[dict]:
    # Unbounded whole-db client ranking is precomputed in client_totals.
    if since is None:
        from app import rollups
        served = rollups.read_top_clients(limit)
        if served is not None:
            return served
    if detect_schema().has_id_storage:
        return _top_clients_id(since, limit)
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
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "ip": r["client_ip"],
            "name": _display_name(r["client_name"], r["client_ip"], resolved, manual),
            "count": r["n"],
        }
        for r in rows
    ]


def _top_clients_id(since: int | None, limit: int) -> list[dict]:
    """Fast path: GROUP BY the raw integer client id (avoids resolving every
    row's ip through the view's subquery), then MERGE by resolved ip. The
    merge is essential: client_by_id is not injective on ip, so two ids can
    map to one client and the trusted view groups by ip. Client cardinality
    is tiny, so fetching every client group (no SQL LIMIT) then sorting in
    Python is cheap and lets the merge happen before the top-N cut."""
    with _connect() as conn:
        where_sql, params = _id_where(since=since)
        rows = conn.execute(
            f"SELECT q.client AS cid, COUNT(*) AS n FROM query_storage q "
            f"WHERE {where_sql} GROUP BY q.client",
            params,
        ).fetchall()
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)
    merged: dict = {}
    for r in rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        merged[ip] = merged.get(ip, 0) + r["n"]
    ordered = sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {"ip": ip, "name": _display_name(namemap.get(ip), ip, resolved, manual), "count": n}
        for ip, n in ordered
    ]


def query_types(client: str | list[str] | None, since: int | None, until: int | None = None) -> list[dict]:
    """Count of queries grouped by FTL query type, most frequent first."""
    # Unbounded, no client: query_type_totals holds this exactly. A client filter
    # has no rollup breakdown (would need a new table), and a bound isn't the
    # "All" range -- both fall through to the direct scan unchanged.
    if client is None and since is None and until is None:
        from app import rollups
        served = rollups.read_query_types()
        if served is not None:
            return served
    if detect_schema().has_id_storage:
        return _query_types_id(client, since, until)
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


def _query_types_id(client: str | list[str] | None, since: int | None, until: int | None) -> list[dict]:
    """Fast path: `type` is a raw column on query_storage, so the view's
    per-row domain/client resolution was pure overhead here — group directly."""
    with _connect() as conn:
        client_ids = _client_ids_for_client_filter(conn, client)
        where_sql, params = _id_where(client_ids=client_ids, since=since, until=until)
        rows = conn.execute(
            f"SELECT q.type AS type_code, COUNT(*) AS n FROM query_storage q "
            f"WHERE {where_sql} GROUP BY q.type ORDER BY n DESC",
            params,
        ).fetchall()
    return [
        {"type_code": r["type_code"], "type": type_name(r["type_code"]), "count": r["n"]}
        for r in rows
    ]


def timeseries(
    client: str | list[str] | None,
    since: int | None,
    until: int | None,
    buckets: int = 60,
) -> dict:
    """Allowed/blocked query counts bucketed evenly across the time window.

    Returns fixed-width buckets (including empty ones) so the frontend can draw
    a continuous chart without inferring gaps. When `since` is unknown (range
    "all"), the window is derived from the data's own min/max timestamp.
    """
    # Unbounded, no client: the rollup cache serves this as day-aligned buckets
    # (see #2) instead of this function's usual arbitrary-width bucketing --
    # a deliberate, disclosed behavior change for the "All" range specifically.
    if client is None and since is None and until is None:
        from app import rollups
        served = rollups.read_timeseries()
        if served is not None:
            return served
    if detect_schema().has_id_storage:
        return _timeseries_id(client, since, until, buckets)
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


def _timeseries_id(
    client: str | list[str] | None, since: int | None, until: int | None, buckets: int
) -> dict:
    """Fast path for timeseries: identical bucketing/series assembly as the
    view-based path, but bucketed/summed directly on query_storage's raw
    timestamp/status columns (no per-row domain/client resolution). Only the
    client filter needs id translation."""
    blocked_in = ",".join(str(s) for s in BLOCKED_STATUSES)
    allowed_in = ",".join(str(s) for s in ALLOWED_STATUSES)

    with _connect() as conn:
        client_ids = _client_ids_for_client_filter(conn, client)

        win_until = until if until else int(time.time())
        if since:
            win_since = since
        else:
            base_where, base_params = _id_where(client_ids=client_ids, until=until)
            row = conn.execute(
                f"SELECT MIN(q.timestamp) AS mn FROM query_storage q WHERE {base_where}",
                base_params,
            ).fetchone()
            win_since = row["mn"] if row and row["mn"] is not None else win_until

        span = max(1, win_until - win_since)
        buckets = max(1, min(buckets, 500))
        width = max(1, span // buckets)

        where_sql, params = _id_where(client_ids=client_ids, since=win_since, until=win_until)
        sql = f"""
            SELECT
                CAST((q.timestamp - ?) / ? AS INTEGER) AS bucket,
                SUM(CASE WHEN q.status IN ({allowed_in}) THEN 1 ELSE 0 END) AS allowed,
                SUM(CASE WHEN q.status IN ({blocked_in}) THEN 1 ELSE 0 END) AS blocked,
                COUNT(*) AS total
            FROM query_storage q
            WHERE {where_sql}
            GROUP BY bucket
            ORDER BY bucket
        """
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
    # Unbounded: same day-aligned rollup fast path as timeseries() (#2).
    if since is None and until is None:
        from app import rollups
        served = rollups.read_client_activity(limit)
        if served is not None:
            return served
    if detect_schema().has_id_storage:
        return _client_activity_id(since, until, limit, buckets)
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

    resolved = resolve.get_names()
    manual = names.get_names()
    result = []
    for t in top:
        ip = t["client_ip"]
        bmap = spark_by_ip.get(ip, {})
        result.append({
            "ip": ip,
            "name": _display_name(t["client_name"], ip, resolved, manual),
            "count": t["n"],
            "first_seen": firsts.get(ip),
            "last_seen": t["last_seen"],
            "sparkline": [bmap.get(i, 0) for i in range(n_buckets)],
        })
    return result


def _client_activity_id(
    since: int | None, until: int | None, limit: int, buckets: int
) -> list[dict]:
    """Fast path for client_activity. Same three-step shape as the view path
    (top-N in window, global first-seen for those, sparkline buckets), but
    grouped on the raw client id and MERGED by resolved ip at each step, so a
    client seen under two ids stays a single row with summed counts, min
    first-seen, max last-seen, and summed sparkline buckets — matching the
    view's group-by-resolved-ip semantics."""
    with _connect() as conn:
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)

        win_until = until if until else int(time.time())
        if since:
            win_since = since
        else:
            base_where, base_params = _id_where(until=until)
            mn = conn.execute(
                f"SELECT MIN(q.timestamp) AS mn FROM query_storage q WHERE {base_where}",
                base_params,
            ).fetchone()["mn"]
            win_since = mn if mn is not None else win_until

        span = max(1, win_until - win_since)
        buckets = max(1, min(buckets, 200))
        width = max(1, span // buckets)
        n_buckets = int(span // width) + 1

        where_sql, params = _id_where(since=win_since, until=win_until)
        # 1) Per-id count/last_seen in the window, merged to per-ip.
        raw_top = conn.execute(
            f"""
            SELECT q.client AS cid, COUNT(*) AS n, MAX(q.timestamp) AS last_seen
            FROM query_storage q
            WHERE {where_sql}
            GROUP BY q.client
            """,
            params,
        ).fetchall()
        by_ip: dict = {}
        for r in raw_top:
            ip = _resolve_client_value(r["cid"], ipmap)
            if ip in by_ip:
                by_ip[ip]["n"] += r["n"]
                by_ip[ip]["last_seen"] = max(by_ip[ip]["last_seen"], r["last_seen"])
            else:
                by_ip[ip] = {"n": r["n"], "last_seen": r["last_seen"]}
        top = sorted(by_ip.items(), key=lambda kv: kv[1]["n"], reverse=True)[:limit]
        if not top:
            return []

        top_ips = [ip for ip, _ in top]
        ids = _ids_for_ips(ipmap, top_ips)
        placeholders = ",".join("?" for _ in ids)

        # 2) Global (unwindowed) first-seen for the selected clients' ids.
        firsts: dict = {}
        for r in conn.execute(
            f"SELECT q.client AS cid, MIN(q.timestamp) AS fs FROM query_storage q "
            f"WHERE q.client IN ({placeholders}) GROUP BY q.client",
            ids,
        ):
            ip = _resolve_client_value(r["cid"], ipmap)
            firsts[ip] = r["fs"] if ip not in firsts else min(firsts[ip], r["fs"])

        # 3) Sparkline buckets, merged per (ip, bucket).
        spark_by_ip: dict = {}
        for r in conn.execute(
            f"""
            SELECT q.client AS cid, CAST((q.timestamp - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS n
            FROM query_storage q
            WHERE {where_sql} AND q.client IN ({placeholders})
            GROUP BY q.client, bucket
            """,
            [win_since, width, *params, *ids],
        ):
            ip = _resolve_client_value(r["cid"], ipmap)
            b = spark_by_ip.setdefault(ip, {})
            b[r["bucket"]] = b.get(r["bucket"], 0) + r["n"]

    resolved = resolve.get_names()
    manual = names.get_names()
    result = []
    for ip, agg in top:
        bmap = spark_by_ip.get(ip, {})
        result.append({
            "ip": ip,
            "name": _display_name(namemap.get(ip), ip, resolved, manual),
            "count": agg["n"],
            "first_seen": firsts.get(ip),
            "last_seen": agg["last_seen"],
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
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "ip": r["client_ip"],
            "name": _display_name(r["client_name"], r["client_ip"], resolved, manual),
            "count": r["n"],
        }
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
        vendor_fields = _vendor_fields(ip, _client_vendor_map(conn))
    name = _display_name(row["client_name"] if row else None, ip, resolve.get_names(), names.get_names())
    return {
        "ip": ip,
        "name": name,
        "first_seen": row["fs"] if row else None,
        "last_seen": row["ls"] if row else None,
        "summary": summary(ip, since, until),
        "top_domains": top_domains(ip, since, limit=10),
        "query_types": query_types(ip, since, until),
        "timeseries": timeseries(ip, since, until, buckets=40),
        "entropy": client_entropy_summary(ip, since),
        **vendor_fields,
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
    if detect_schema().has_id_storage:
        return _new_clients_id(after_ts)
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
    resolved = resolve.get_names()
    manual = names.get_names()
    return [
        {
            "ip": r["client_ip"],
            "name": _display_name(r["client_name"], r["client_ip"], resolved, manual),
            "first_seen": r["first_seen"],
            "total": r["total"],
        }
        for r in rows
    ]


def _new_clients_id(after_ts: int) -> list[dict]:
    """Fast path: MIN(timestamp)/COUNT grouped on the raw client id (no per-row
    ip subquery), then MERGE by resolved ip before applying the first-seen
    cutoff. Merging first is required for correctness: a client seen under two
    ids has one true global first-seen (the min across both) and one total."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT q.client AS cid, MIN(q.timestamp) AS fs, COUNT(*) AS total "
            "FROM query_storage q GROUP BY q.client"
        ).fetchall()
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)
    merged: dict = {}
    for r in rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        if ip in merged:
            fs, total = merged[ip]
            merged[ip] = (min(fs, r["fs"]), total + r["total"])
        else:
            merged[ip] = (r["fs"], r["total"])
    resolved = resolve.get_names()
    manual = names.get_names()
    out = [
        {
            "ip": ip,
            "name": _display_name(namemap.get(ip), ip, resolved, manual),
            "first_seen": fs,
            "total": total,
        }
        for ip, (fs, total) in merged.items()
        if fs >= after_ts
    ]
    out.sort(key=lambda c: c["first_seen"], reverse=True)
    return out


def vendor_alert_candidates(after_ts: int) -> list[dict]:
    """New clients (see new_clients) classified for the new_vendor alert rule
    (#12), complementary to new_device: that rule fires on any new IP,
    regardless of vendor; this one is keyed on the vendor itself.

    Returns [] entirely when this schema carries no vendor data at all (#4) --
    flagging "unrecognized vendor" for every new device would be a false
    signal from a data gap, not an actual unrecognized-hardware finding.

    Each entry is {"ip", "name", "first_seen", "vendor", "kind"}, where kind is:
      - "unrecognized": no vendor could be resolved for this device at all
        (no MAC captured, a randomized/private MAC, or a real MAC with no
        match in Pi-hole's own table or our offline OUI fallback).
      - "new_vendor": a vendor WAS resolved, but no other client that already
        existed before this window carries that same vendor string -- the
        network's first device from that manufacturer.
    A resolved vendor already seen on an established (pre-window) client is
    not a candidate at all -- e.g. "another device from the vendor you
    already have" isn't noteworthy.
    """
    if not detect_schema().has_vendor_data:
        return []
    new = new_clients(after_ts)
    if not new:
        return []
    with _connect() as conn:
        vmap = _client_vendor_map(conn)
    new_ips = {c["ip"] for c in new}
    established_vendors = {
        v["vendor"] for ip, v in vmap.items() if ip not in new_ips and v.get("vendor")
    }
    out = []
    for c in new:
        v = _vendor_fields(c["ip"], vmap)
        vendor = v["vendor"]
        if vendor and vendor in established_vendors:
            continue
        kind = "new_vendor" if vendor else "unrecognized"
        out.append({
            "ip": c["ip"],
            "name": c["name"],
            "first_seen": c["first_seen"],
            "vendor": vendor,
            "kind": kind,
        })
    return out


# --------------------------------------------------------------------------
# DoH/DoT provider detection (#33, scope-corrected)
#
# This does NOT detect DNS-over-HTTPS/VPN *bypass* traffic itself -- once a
# device fully commits to routing its DNS through DoH/DoT (or a full-tunnel
# VPN), none of that traffic is plain DNS anymore, so nothing reaches
# Pi-hole to see it (see README's "Honest scope" note, which already
# discloses this blind spot). What IS still visible is a client querying one
# of a well-known provider's OWN domains -- the DoH/DoT setup/provisioning
# handshake, or a periodic plain-DNS fallback query some clients keep making
# even after switching over. That is a legitimate, narrow, proxy signal
# ("this device may be about to route some DNS around Pi-hole"), and this
# module is careful to only ever claim exactly that, not "bypass detected".
#
# Deliberately a small maintained constant, not user-configurable in v1 --
# matching the OUI/vendor fallback table's precedent elsewhere in this file.
# --------------------------------------------------------------------------

DOH_PROVIDER_DOMAINS = {
    "cloudflare-dns.com",     # Cloudflare 1.1.1.1 (incl. mozilla.cloudflare-dns.com, Firefox's TRR)
    "dns.google",             # Google Public DNS
    "doh.opendns.com",        # Cisco OpenDNS
    "dns.opendns.com",
    "dns.quad9.net",          # Quad9
    "doh.cleanbrowsing.org",  # CleanBrowsing
    "dns.nextdns.io",         # NextDNS (per-user config is a subdomain of this)
    "dns.adguard.com",        # AdGuard DNS
    "doh.libredns.gr",        # LibreDNS
}


def _match_doh_provider(domain: str | None) -> str | None:
    """The known provider domain `domain` belongs to (exact match or a
    subdomain of one), or None. Suffix matching (rather than an unbounded
    LIKE %provider%) is deliberate -- e.g. NextDNS issues each user a
    subdomain like abc123.dns.nextdns.io, and this must not accidentally
    match an unrelated domain that merely contains "dns.google" as a
    substring somewhere in an unrelated label."""
    if not domain:
        return None
    d = domain.lower()
    for p in DOH_PROVIDER_DOMAINS:
        if d == p or d.endswith("." + p):
            return p
    return None


def _merge_doh_hit(merged: dict, ip: str | None, name, provider: str | None, count: int, last_seen) -> None:
    if not ip or not provider:
        return
    key = (ip, provider)
    if key in merged:
        merged[key]["count"] += count
        merged[key]["last_seen"] = max(merged[key]["last_seen"], last_seen)
    else:
        merged[key] = {"ip": ip, "name": name, "provider": provider, "count": count, "last_seen": last_seen}


def doh_provider_hits(since: int) -> list[dict]:
    """Clients that queried a known DoH/DoT provider's own domain at or after
    `since` (see DOH_PROVIDER_DOMAINS and the module note above for exactly
    what this is -- and is NOT -- evidence of).

    One entry per (client, matched provider domain): {"ip", "name",
    "provider", "count", "last_seen"}, most-recent first. Matching is an
    exact/suffix check against the small fixed provider list (see
    _match_doh_provider), not an unbounded substring LIKE scan.
    """
    if detect_schema().has_id_storage:
        return _doh_provider_hits_id(since)
    select, join = _client_join_sql()
    conds = []
    params: list = [since]
    for p in DOH_PROVIDER_DOMAINS:
        conds.append("q.domain = ? OR q.domain LIKE ?")
        params.append(p)
        params.append(f"%.{p}")
    where_domains = " OR ".join(f"({c})" for c in conds)
    sql = f"""
        SELECT {select}, q.domain AS domain, MAX(q.timestamp) AS last_seen, COUNT(*) AS n
        FROM queries q
        {join}
        WHERE q.timestamp >= ? AND ({where_domains})
        GROUP BY {_client_ip_col()}, q.domain
    """
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    resolved = resolve.get_names()
    manual = names.get_names()
    merged: dict = {}
    for r in rows:
        provider = _match_doh_provider(r["domain"])
        name = _display_name(r["client_name"], r["client_ip"], resolved, manual)
        _merge_doh_hit(merged, r["client_ip"], name, provider, r["n"], r["last_seen"])
    out = list(merged.values())
    out.sort(key=lambda c: c["last_seen"], reverse=True)
    return out


def _doh_provider_hits_id(since: int) -> list[dict]:
    """doh_provider_hits fast path for the normalized (has_id_storage) schema:
    resolve matching domain ids from domain_by_id once (a small, fixed
    provider list -- never an unbounded scan), then filter query_storage on
    those raw ids directly, mirroring count_queries's domain-filter fast path."""
    with _connect() as conn:
        conds = []
        params: list = []
        for p in DOH_PROVIDER_DOMAINS:
            conds.append("domain = ? OR domain LIKE ?")
            params.append(p)
            params.append(f"%.{p}")
        where_domains = " OR ".join(f"({c})" for c in conds)
        domain_rows = conn.execute(
            f"SELECT id, domain FROM domain_by_id WHERE {where_domains}", params
        ).fetchall()
        if not domain_rows:
            return []
        domain_provider = {r["id"]: _match_doh_provider(r["domain"]) for r in domain_rows}
        ids = list(domain_provider.keys())
        ph = ",".join("?" for _ in ids)
        rows = conn.execute(
            f"SELECT q.client AS cid, q.domain AS did, MAX(q.timestamp) AS last_seen, COUNT(*) AS n "
            f"FROM query_storage q WHERE q.domain IN ({ph}) AND q.timestamp >= ? "
            f"GROUP BY q.client, q.domain",
            [*ids, since],
        ).fetchall()
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)
    resolved = resolve.get_names()
    manual = names.get_names()
    merged: dict = {}
    for r in rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        provider = domain_provider.get(r["did"])
        name = _display_name(namemap.get(ip), ip, resolved, manual) if ip else None
        _merge_doh_hit(merged, ip, name, provider, r["n"], r["last_seen"])
    out = list(merged.values())
    out.sort(key=lambda c: c["last_seen"], reverse=True)
    return out


# --------------------------------------------------------------------------
# Cross-client domain fan-out (#34)
#
# "Which domains got hit by several distinct clients within the same SHORT
# window" -- surfaces synchronized beaconing (several IoT devices phoning the
# same tracker/C2 near-simultaneously) that a per-client view structurally
# can't show. Deliberately NOT "count distinct clients over the whole
# selected range": a CDN/ad/telemetry domain is *supposed* to be hit by every
# device over a long enough range, so that flat count would be constantly
# noisy on completely benign traffic (the exact false-positive both the
# Claude and Codex product-review scopings for this issue flagged). Requiring
# the distinct clients to cluster into one short bucket is what actually
# signals "near-simultaneous", not "generally popular".
#
# Deliberately a bounded-range-only, on-demand view (like Live Stream /
# Blocklist Simulator / Client Heatmaps) -- not a rollup-backed "All" mode and
# not an alert rule. Uses the `queries` view directly (same as list_queries/
# tail_queries), which is fine for a bounded window; the per-row correlated
# subquery cost this module works hard to avoid elsewhere is specifically a
# WHOLE-TABLE-unbounded-scan problem (see the has_id_storage module note),
# not a bounded-range one.
# --------------------------------------------------------------------------

FANOUT_MAX_LOOKBACK_SECONDS = 7 * 86400  # mirrors simulate_pattern's 7-day cap
FANOUT_LIMIT = 50


def domain_fanout(
    since: int | None,
    until: int | None = None,
    bucket_minutes: int = 5,
    min_clients: int = 3,
    limit: int = FANOUT_LIMIT,
) -> list[dict]:
    """Domains queried by >= min_clients distinct clients within one
    bucket_minutes-wide window, most-clients-first. Each entry: {"domain",
    "window_start", "window_end", "client_count", "query_count", "clients":
    [{"ip", "name"}, ...]}.

    `since` is hard-capped to FANOUT_MAX_LOOKBACK_SECONDS -- this is a
    bounded-range view, never an "All" scan (see module note above).

    Buckets are FIXED windows anchored to `since` (bucket N covers
    [since + N*bucket_seconds, since + (N+1)*bucket_seconds)), not a sliding
    window -- a genuine burst that happens to straddle one of these fixed
    boundaries could split across two buckets and under-count. Accepted
    tradeoff for v1: a sliding window is the correct fix but meaningfully
    more expensive to compute, and a real synchronized burst (queries within
    seconds of each other, not minutes) is overwhelmingly unlikely to land
    exactly on a boundary in practice.
    """
    now = int(time.time())
    until = until if until is not None else now
    earliest = now - FANOUT_MAX_LOOKBACK_SECONDS
    since = earliest if since is None else max(since, earliest)
    bucket_seconds = max(60, int(bucket_minutes) * 60)

    if detect_schema().has_id_storage:
        return _domain_fanout_id(since, until, bucket_seconds, min_clients, limit)

    select, join = _client_join_sql()
    client_col = _client_ip_col()
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT q.domain AS domain,
                   CAST((q.timestamp - ?) / ? AS INTEGER) AS bucket,
                   COUNT(DISTINCT {client_col}) AS client_count,
                   COUNT(*) AS query_count
            FROM queries q
            {join}
            WHERE q.timestamp >= ? AND q.timestamp < ?
            GROUP BY q.domain, bucket
            HAVING client_count >= ?
            ORDER BY client_count DESC, bucket DESC
            LIMIT ?
            """,
            [since, bucket_seconds, since, until, min_clients, limit],
        ).fetchall()

        resolved = resolve.get_names()
        manual = names.get_names()
        out = []
        for r in rows:
            window_start = since + r["bucket"] * bucket_seconds
            window_end = window_start + bucket_seconds
            # A bounded follow-up per qualifying (domain, window) pair -- capped
            # at `limit` rows total, so at most `limit` extra queries for an
            # on-demand exploratory view, not a hot path. Reuses the same
            # select/join as the aggregate above so Pi-hole's own client_name
            # (not just the bare ip) resolves correctly.
            crows = conn.execute(
                f"""
                SELECT DISTINCT {select}
                FROM queries q
                {join}
                WHERE q.domain = ? AND q.timestamp >= ? AND q.timestamp < ?
                """,
                [r["domain"], window_start, window_end],
            ).fetchall()
            clients = [
                {
                    "ip": c["client_ip"],
                    "name": _display_name(c["client_name"], c["client_ip"], resolved, manual),
                }
                for c in crows
            ]
            out.append({
                "domain": r["domain"],
                "window_start": window_start,
                "window_end": window_end,
                "client_count": r["client_count"],
                "query_count": r["query_count"],
                "clients": clients,
            })
    return out


def _domain_fanout_id(
    since: int, until: int, bucket_seconds: int, min_clients: int, limit: int
) -> list[dict]:
    """domain_fanout fast path for the normalized (has_id_storage) schema.

    The view-based query above pays the `queries` view's per-row correlated
    subquery for EVERY row in the window before it can even group/filter --
    unlike list_queries/tail_queries, a GROUP BY can't stop early via
    ORDER BY+LIMIT on an index. Measured against the real UAT snapshot: 1.7s
    for a 7-day window through the view vs. ~0.3s scanning query_storage's raw
    columns directly (verified below).

    Grouping by the raw domain id is safe (domain_by_id is a bijection, same
    invariant every other id-based aggregate in this module relies on).
    COUNT(DISTINCT client) on the raw id is NOT safe on its own -- two ids can
    map to the same ip (the duplicate-ip trap) -- but it can only OVER-count,
    never under-count, so filtering candidates on the raw threshold can't drop
    a genuine match; it can only admit a few false ones. Those are corrected
    by resolving ids to ips and recomputing the TRUE distinct-ip count per
    candidate, then re-filtering/re-sorting on that before slicing to `limit`.
    """
    # Wide enough that re-filtering by the true (never higher) resolved-ip
    # count still leaves enough rows to fill `limit`, bounded so the
    # per-candidate follow-up queries below can't run away on a large limit.
    candidate_pool = min(max(limit * 4, 200), 500)
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT domain AS did, CAST((timestamp - ?) / ? AS INTEGER) AS bucket,
                   COUNT(DISTINCT client) AS raw_client_count, COUNT(*) AS query_count
            FROM query_storage
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY domain, bucket
            HAVING raw_client_count >= ?
            ORDER BY raw_client_count DESC, bucket DESC
            LIMIT ?
            """,
            [since, bucket_seconds, since, until, min_clients, candidate_pool],
        ).fetchall()
        if not rows:
            return []

        dmap = _domain_text_map(conn)
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)
        resolved = resolve.get_names()
        manual = names.get_names()

        out = []
        for r in rows:
            domain = _resolve_domain_value(r["did"], dmap)
            if domain is None:  # orphaned id -- no real domain to attribute this to
                continue
            window_start = since + r["bucket"] * bucket_seconds
            window_end = window_start + bucket_seconds
            # Small, bounded follow-up (one bucket's worth of one domain's
            # rows), same shape as the view-based path's own per-candidate
            # query -- just against the raw table instead of the view.
            crows = conn.execute(
                "SELECT DISTINCT client FROM query_storage "
                "WHERE domain = ? AND timestamp >= ? AND timestamp < ?",
                [r["did"], window_start, window_end],
            ).fetchall()
            ips = {_resolve_client_value(c["client"], ipmap) for c in crows}
            ips.discard(None)
            if len(ips) < min_clients:
                continue
            clients = [
                {"ip": ip, "name": _display_name(namemap.get(ip), ip, resolved, manual)}
                for ip in ips
            ]
            out.append({
                "domain": domain,
                "window_start": window_start,
                "window_end": window_end,
                "client_count": len(ips),
                "query_count": r["query_count"],
                "clients": clients,
            })
        out.sort(key=lambda x: (x["client_count"], x["window_start"]), reverse=True)
        return out[:limit]


# --------------------------------------------------------------------------
# DNS-tunneling / exfiltration detector (#2 in the feature backlog): a
# genuinely different axis from domain_fanout above (which looks at MANY
# clients hitting ONE domain) -- this looks at ONE client emitting a large
# number of distinct subdomains under a single REGISTERED parent domain
# (classic iodine/dnscat2-style tunneling, and some exfil tooling). Grouping
# by PSL-aware registered parent (see app/psl.py) rather than naive
# last-two-labels avoids two failure modes: misidentifying the parent on
# multi-part suffixes like co.uk, and mistakenly treating a shared CDN/cloud
# host (*.s3.amazonaws.com) as one entity when it's actually many unrelated
# tenants.
#
# Deliberately an ON-DEMAND panel, never an alert rule (see the feature
# backlog's own scoping note): CDN/cloud subdomains are also
# high-cardinality/random-looking, so this has real false-positive risk on a
# typical home network and needs a human reading it, not a page.
# --------------------------------------------------------------------------

TUNNELING_MAX_LOOKBACK_SECONDS = 7 * 86400  # mirrors domain_fanout's cap
TUNNELING_MIN_DISTINCT_DEFAULT = 20
TUNNELING_LIMIT_DEFAULT = 25
_TUNNELING_SAMPLE_SIZE = 5


def _tunneling_group(rows: list[tuple]) -> list[dict]:
    """Shared aggregation for both schema paths below: rows is a list of
    (ip, domain, count) already GROUP BY'd in SQL (so repeat queries for the
    same domain collapse to one entry before the Python-side PSL grouping,
    keeping this loop's cost proportional to DISTINCT (client, domain) pairs,
    not raw query volume)."""
    groups: dict[tuple[str, str], dict] = {}
    for ip, domain, count in rows:
        if ip is None or domain is None:
            continue
        parent = psl.registered_domain(domain)
        key = (ip, parent)
        g = groups.setdefault(key, {"subdomains": set(), "query_count": 0, "prefix_lens": []})
        g["subdomains"].add(domain)
        g["query_count"] += count
        # Length of whatever sits to the left of the registered parent -- a
        # long/high-entropy prefix under one parent is the actual tunneling
        # signature; the parent domain's own length says nothing about it.
        if len(domain) > len(parent):
            g["prefix_lens"].append(len(domain) - len(parent) - 1)  # -1 for the dot
        else:
            g["prefix_lens"].append(0)
    out = []
    for (ip, parent), g in groups.items():
        out.append({
            "ip": ip,
            "parent_domain": parent,
            "distinct_subdomains": len(g["subdomains"]),
            "query_count": g["query_count"],
            "avg_prefix_length": round(statistics.mean(g["prefix_lens"]), 1),
            "sample_subdomains": sorted(g["subdomains"])[:_TUNNELING_SAMPLE_SIZE],
        })
    return out


def tunneling_candidates(
    since: int | None,
    until: int | None = None,
    min_distinct: int = TUNNELING_MIN_DISTINCT_DEFAULT,
    limit: int = TUNNELING_LIMIT_DEFAULT,
) -> list[dict]:
    """Per-(client, registered-parent-domain) groups with an unusually high
    number of distinct subdomains within the window -- see module note above.
    Each entry: {"ip", "name", "parent_domain", "distinct_subdomains",
    "query_count", "avg_prefix_length", "sample_subdomains"}, sorted by
    distinct_subdomains descending.

    `since` is hard-capped to TUNNELING_MAX_LOOKBACK_SECONDS, same
    bounded-range-only contract as domain_fanout (never an "All" scan).
    """
    now = int(time.time())
    until = until if until is not None else now
    earliest = now - TUNNELING_MAX_LOOKBACK_SECONDS
    since = earliest if since is None else max(since, earliest)

    if detect_schema().has_id_storage:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT client, domain, COUNT(*) AS cnt FROM query_storage "
                "WHERE timestamp >= ? AND timestamp < ? GROUP BY client, domain",
                [since, until],
            ).fetchall()
            ipmap = _client_ip_map(conn)
            dmap = _domain_text_map(conn)
            resolved_pairs = [
                (_resolve_client_value(r["client"], ipmap), _resolve_domain_value(r["domain"], dmap), r["cnt"])
                for r in rows
            ]
            namemap = _client_name_map(conn)
    else:
        select, join = _client_join_sql()
        client_col = _client_ip_col()
        with _connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {client_col} AS ip, q.domain AS domain, COUNT(*) AS cnt
                FROM queries q
                {join}
                WHERE q.timestamp >= ? AND q.timestamp < ?
                GROUP BY {client_col}, q.domain
                """,
                [since, until],
            ).fetchall()
            resolved_pairs = [(r["ip"], r["domain"], r["cnt"]) for r in rows]
            # Not every schema shape has a name-bearing network_addresses table
            # in the shape _client_name_map assumes (see its own docstring --
            # that's a "real"/idstore-only source); reuse the same select/join
            # every other view-path function uses for names instead, same
            # idiom as new_clients() above.
            name_rows = conn.execute(
                f"SELECT DISTINCT {select} FROM queries q {join} "
                "WHERE q.timestamp >= ? AND q.timestamp < ?",
                [since, until],
            ).fetchall()
            namemap = {r["client_ip"]: r["client_name"] for r in name_rows}

    resolved = resolve.get_names()
    manual = names.get_names()
    groups = _tunneling_group(resolved_pairs)
    out = [g for g in groups if g["distinct_subdomains"] >= min_distinct]
    for g in out:
        g["name"] = _display_name(namemap.get(g["ip"]), g["ip"], resolved, manual)
    out.sort(key=lambda x: x["distinct_subdomains"], reverse=True)
    return out[:limit]


def slowest_domains(
    since: int | None, until: int | None, min_count: int = 5, limit: int = 15
) -> list[dict]:
    """Domains ranked by average resolution latency (Pi-hole's own
    `reply_time`, recorded in seconds) over the range -- surfaces slow,
    uncached, or upstream-forwarded lookups a per-client view can't show on
    its own (#47).

    Only meaningful on Pi-hole's normalized (has_id_storage) on-disk layout
    -- `reply_time` doesn't exist on the older client-table/plain-TEXT
    `queries` layouts at all, so this returns [] entirely rather than
    erroring on those, the same honest-scope precedent has_vendor_data
    already established elsewhere in this file. (`dnssec`/`ede` are also
    normalized-only columns, but were deliberately NOT turned into an alert
    rule here: checked against the real UAT snapshot and `dnssec` is 0 for
    every one of its 1.1M rows -- DNSSEC validation is opt-in in Pi-hole and
    off by default, so a "DNSSEC failure" rule would be dead code for most
    real deployments. `ede` had only 53 non-"-1" rows in that same snapshot,
    both resolver-side network-error codes rather than anything actionable
    as a security signal -- not enough real support to justify a rule.)

    `min_count` guards against a single one-off slow lookup dominating the
    ranking: a domain queried once at 2s "looks slow" but isn't a pattern
    the way a domain that's consistently slow across many queries is.
    """
    if not detect_schema().has_id_storage:
        return []
    where = ["reply_time IS NOT NULL"]
    params: list = []
    if since:
        where.append("timestamp >= ?")
        params.append(since)
    if until:
        where.append("timestamp <= ?")
        params.append(until)
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT domain AS did, AVG(reply_time) AS avg_reply,
                   MAX(reply_time) AS max_reply, COUNT(*) AS query_count
            FROM query_storage
            WHERE {" AND ".join(where)}
            GROUP BY domain
            HAVING COUNT(*) >= ?
            ORDER BY avg_reply DESC
            LIMIT ?
            """,
            [*params, min_count, limit],
        ).fetchall()
        dmap = _domain_text_map(conn)
    out = []
    for r in rows:
        domain = _resolve_domain_value(r["did"], dmap)
        if domain is None:  # orphaned id -- no real domain to attribute this to
            continue
        out.append({
            "domain": domain,
            "avg_reply_ms": round(r["avg_reply"] * 1000, 1),
            "max_reply_ms": round(r["max_reply"] * 1000, 1),
            "query_count": r["query_count"],
        })
    return out


def domain_queriers(domain: str, since: int, until: int) -> list[str]:
    """Distinct client ips that queried `domain` (exact match) within
    [since, until) -- backs the correlated_new_device_domain alert rule
    (#46), which needs to know WHO queried a just-first-seen domain so it
    can check whether any of them is also a brand-new client. A small,
    bounded, single-domain lookup (not a hot-path aggregate), so this
    doesn't need domain_fanout's id-based fast path treatment."""
    if detect_schema().has_id_storage:
        with _connect() as conn:
            row = conn.execute(
                "SELECT id FROM domain_by_id WHERE domain = ?", [domain]
            ).fetchone()
            if row is None:  # never actually stored under this exact text -- no queriers
                return []
            ipmap = _client_ip_map(conn)
            rows = conn.execute(
                "SELECT DISTINCT client FROM query_storage "
                "WHERE domain = ? AND timestamp >= ? AND timestamp < ?",
                [row["id"], since, until],
            ).fetchall()
        ips = {_resolve_client_value(r["client"], ipmap) for r in rows}
        ips.discard(None)
        return sorted(ips)

    _, join = _client_join_sql()
    client_col = _client_ip_col()
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT DISTINCT {client_col} AS ip FROM queries q {join} "
            "WHERE q.domain = ? AND q.timestamp >= ? AND q.timestamp < ?",
            [domain, since, until],
        ).fetchall()
    return sorted(r["ip"] for r in rows if r["ip"] is not None)


def unusual_query_types(window_minutes: int) -> list[dict]:
    """Clients using a DNS query type in the last `window_minutes` that they
    have never used in ANY of their prior history -- a shift in query-type
    COMPOSITION, not volume (#55). A classic tunneling/exfil signature
    (e.g. a device that's only ever done A/AAAA suddenly doing TXT/ANY
    lookups) that volume_threshold can't see, since it counts queries, not
    what kind they are.

    A client with NO history before the window is skipped entirely -- a
    brand-new device's first-ever queries are definitionally "new query
    types it's never used before" for every type it happens to use, which
    would make this fire constantly for new_device and add nothing
    new_device/new_vendor don't already cover.

    Each entry: {"ip", "name", "new_types": [...]} -- new_types is the
    resolved type names (e.g. "TXT", "ANY"), sorted for a stable message.
    """
    now = int(time.time())
    cutoff = now - window_minutes * 60
    out = []
    for c in client_counts(cutoff, now):
        ip = c["ip"]
        established = {t["type_code"] for t in query_types(ip, None, cutoff)}
        if not established:
            continue
        recent = {t["type_code"] for t in query_types(ip, cutoff, now)}
        new_type_codes = recent - established
        if new_type_codes:
            out.append({
                "ip": ip,
                "name": c["name"],
                "new_types": sorted(type_name(tc) for tc in new_type_codes),
            })
    return out


TOP_DOMAINS_LIMIT = 50  # how many matched domains the breakdown returns

# Caps the AGGREGATE wall-clock cost of one simulate_pattern() call, independent
# of _MATCH_TIMEOUT_SECONDS below (which only bounds a single row). Module-level
# so tests can monkeypatch it to something tiny rather than waiting out the real
# budget or crafting a genuinely pathological pattern.
SIMULATE_BUDGET_SECONDS = 30.0


class SimulationBudgetExceeded(Exception):
    """Raised when one simulate_pattern() call runs past its overall
    wall-clock budget. The per-row `regex` timeout below only bounds a
    SINGLE row; it does nothing to cap the aggregate cost of a pattern that
    reliably hits that per-row timeout across many distinct domains in a
    busy window (SECURITY_AUDIT_REPORT.md finding #4 only covered the
    single-row case). main.py maps this to a 503."""


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
    re.compile(pattern)  # validate syntax first; raises re.error on bad input
    # Matched with the third-party `regex` engine (not stdlib `re`) so each
    # per-row match can be time-bounded below. Client names/hostnames come
    # from Pi-hole/DHCP and domains logged here are attacker-influenceable
    # within DNS label limits, so a user-supplied pattern combined with an
    # adversarial domain string can otherwise trigger catastrophic
    # backtracking and hang a worker (ReDoS — see SECURITY_AUDIT_REPORT.md
    # finding #4). A timed-out row is treated as "no match" rather than
    # raising: conservative (only undercounts that one pathological row)
    # and never lets a single row stall the whole scan.
    #
    # Trade-off, deliberately accepted: `regex`'s per-call timeout has real
    # overhead (measured ~6-7x slower per call than a timeout-less search).
    # Across a full 7-day scan that adds a few seconds, not milliseconds —
    # acceptable for a button-triggered batch operation that already opts
    # into exact (not sampled) counts at a real cost, per the docstring
    # above, but worth knowing if this function's latency ever matters more
    # than it does today.
    try:
        timed = _timed_regex.compile(pattern)
    except _timed_regex.error as e:
        # `regex`'s accepted syntax isn't 100% identical to stdlib `re`'s —
        # a pattern that passed the re.compile() check above can still be
        # rejected here. Re-raise as re.error so main.py's existing
        # `except re.error` still maps this to a clean 400 instead of an
        # unhandled 500.
        raise re.error(str(e)) from e
    _MATCH_TIMEOUT_SECONDS = 0.5
    # Caps the AGGREGATE cost of the two scans below, independent of the
    # per-row timeout above. A raised exception inside a SQLite UDF gets
    # flattened by the sqlite3 module into an indistinguishable
    # OperationalError ("user-defined function raised exception"), so instead
    # of raising from _regexp itself, it trips this flag and returns a cheap
    # non-match for every remaining row (no more regex evaluation, just a
    # monotonic-clock comparison) — the query still finishes quickly, and the
    # budget breach is raised as a real Python exception afterwards, once
    # SQLite is done with it.
    deadline = time.monotonic() + SIMULATE_BUDGET_SECONDS
    budget_exceeded = False

    def _regexp(_pattern_arg: str, value: str | None) -> int:
        nonlocal budget_exceeded
        if budget_exceeded:
            return 0
        if time.monotonic() > deadline:
            budget_exceeded = True
            return 0
        try:
            return 1 if timed.search(value or "", timeout=_MATCH_TIMEOUT_SECONDS) else 0
        except TimeoutError:
            return 0

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

    if budget_exceeded:
        raise SimulationBudgetExceeded(
            f"pattern evaluation exceeded the {SIMULATE_BUDGET_SECONDS:.0f}s overall "
            "budget — try a more specific pattern"
        )

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
    resolved = resolve.get_names()
    manual = names.get_names()
    clients = []
    for r in client_rows:
        ip = r["client_ip"]
        matched = r["n"]
        total = client_totals.get(ip, matched)
        clients.append({
            "ip": ip,
            "name": _display_name(r["client_name"], ip, resolved, manual),
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


def _anomaly_inputs(
    now: int, baseline_start: int
) -> tuple[dict[str, dict[int, int]], dict[str, int], dict[str, str]]:
    """Fetch the (per-client hourly buckets, windowed first-seen, names) that
    detect_anomalies analyses. Two implementations with identical outputs:
    the view path (correlated per-row resolution) and the id path (group on
    raw client id, merge by resolved ip).

    "First-seen" here is deliberately the earliest row WITHIN the baseline
    window, not the client's true all-time first query (which would cost an
    extra unwindowed full-table scan, ~0.7s on the real snapshot). It's
    equivalent for both uses downstream: eligibility (`now - fs < 24h`) — a
    client active before the window has a windowed fs at/near baseline_start,
    always >24h old, same conclusion as the true value; and clamping
    (`max(baseline_start, fs)`) — a client whose true first query is within
    the window has an unchanged windowed fs, and an older client collapses to
    ≈baseline_start either way, exactly what the clamp resolves to. (Accepted
    edge case: a client active long ago, silent >7 days, then active again in
    the window reads as "new" rather than "returning" — fine, it has no useful
    recent baseline anyway.)
    """
    if not detect_schema().has_id_storage:
        ccol = _client_ip_col()
        _, join = _client_join_sql()
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
        resolved = resolve.get_names()
        manual = names.get_names()
        display_names = {
            r["client_ip"]: _display_name(r["client_name"], r["client_ip"], resolved, manual)
            for r in first_seen_rows
        }
        per_client_buckets: dict[str, dict[int, int]] = {}
        for r in bucket_rows:
            per_client_buckets.setdefault(r["ip"], {})[r["bucket"]] = r["n"]
        return per_client_buckets, first_seen, display_names

    # Id fast path: group on the raw client id (no per-row ip subquery) and
    # merge by resolved ip, so a client seen under two ids sums its buckets,
    # takes the min first-seen, and appears once — matching the view.
    with _connect() as conn:
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)
        bucket_rows = conn.execute(
            """
            SELECT q.client AS cid,
                   CAST((q.timestamp - ?) / 3600 AS INTEGER) AS bucket,
                   COUNT(*) AS n
            FROM query_storage q
            WHERE q.timestamp >= ? AND q.timestamp <= ?
            GROUP BY q.client, bucket
            """,
            [baseline_start, baseline_start, now],
        ).fetchall()
        first_seen_rows = conn.execute(
            "SELECT q.client AS cid, MIN(q.timestamp) AS fs FROM query_storage q "
            "WHERE q.timestamp >= ? GROUP BY q.client",
            [baseline_start],
        ).fetchall()

    per_client_buckets = {}
    for r in bucket_rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        b = per_client_buckets.setdefault(ip, {})
        b[r["bucket"]] = b.get(r["bucket"], 0) + r["n"]

    first_seen = {}
    for r in first_seen_rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        first_seen[ip] = r["fs"] if ip not in first_seen else min(first_seen[ip], r["fs"])

    resolved = resolve.get_names()
    manual = names.get_names()
    display_names = {ip: _display_name(namemap.get(ip), ip, resolved, manual) for ip in first_seen}
    return per_client_buckets, first_seen, display_names


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

    per_client_buckets, first_seen, display_names = _anomaly_inputs(now, baseline_start)

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
        name = display_names.get(ip, ip)

        if avg > SILENT_MIN_BASELINE_AVG and all(h == 0 for h in recent_series):
            anomalies.append({
                "ip": ip, "name": name, "kind": "silent",
                "baseline_avg": round(avg, 2), "baseline_stddev": round(stddev, 2),
                "current_value": 0,
                "window_since": baseline_end, "window_until": now,
                # Shared with alerts.py's device_quiet rule (#6/#7).
                "presence_note": quiet_presence_note(ip),
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

    anomalies.extend(_nxdomain_anomalies(now, baseline_start))
    return anomalies


# NXDOMAIN-rate anomaly ("this client's failed-lookup rate just jumped") --
# the classic DGA/dead-C2 signature: malware probing generated domains gets
# NXDOMAIN back for nearly all of them, a pattern invisible to every other
# rule here (they key on volume, query *type*, or domain novelty, never the
# *answer*). Only meaningful on Pi-hole's normalized (has_id_storage) layout
# -- `reply_type` doesn't exist on the older client-table/plain-TEXT `queries`
# layouts at all, same honest-scope precedent as slowest_domains()/
# has_vendor_data elsewhere in this file.
NXDOMAIN_REPLY_TYPE = 2  # FTL's `enum reply_type` value for REPLY_NXDOMAIN --
                         # best-effort like BLOCKED_STATUSES/ALLOWED_STATUSES
                         # above; there's no raw value to echo back here since
                         # this is a single int, not a classified set.
NXDOMAIN_WINDOW_HOURS = 3  # matches SILENT_WINDOW_HOURS/the volume spike's "now"
NXDOMAIN_MIN_BASELINE_COUNT = 20  # need a real baseline sample before trusting its rate
NXDOMAIN_MIN_RECENT_COUNT = 10    # ditto for the recent window
NXDOMAIN_MIN_RECENT_NX = 5        # a handful of actual NXDOMAINs, not 1-2 flaky ones
NXDOMAIN_RATE_MULTIPLIER = 3.0    # recent rate must clear 3x its own baseline...
NXDOMAIN_MIN_FLOOR_RATE = 0.15    # ...AND clear an absolute 15% floor, so a client
                                   # with a ~0% baseline (never hit NXDOMAIN before)
                                   # doesn't trip on a trivial 1% blip (0 * 3 = 0).


def _nxdomain_anomalies(now: int, baseline_start: int) -> list[dict]:
    """Per-client NXDOMAIN rate: baseline (everything from `baseline_start`
    up to the recent window) vs. recent (last NXDOMAIN_WINDOW_HOURS). One
    query, partitioned by a CASE on the recent-window boundary, for the same
    reason detect_anomalies() batches its volume query: this must never add
    a second full-table scan per client."""
    if not detect_schema().has_id_storage:
        return []
    recent_start = now - NXDOMAIN_WINDOW_HOURS * 3600
    with _connect() as conn:
        ipmap = _client_ip_map(conn)
        namemap = _client_name_map(conn)
        rows = conn.execute(
            """
            SELECT q.client AS cid,
                   CASE WHEN q.timestamp >= ? THEN 1 ELSE 0 END AS is_recent,
                   SUM(CASE WHEN q.reply_type = ? THEN 1 ELSE 0 END) AS nx,
                   COUNT(*) AS total
            FROM query_storage q
            WHERE q.timestamp >= ?
            GROUP BY q.client, is_recent
            """,
            [recent_start, NXDOMAIN_REPLY_TYPE, baseline_start],
        ).fetchall()

    per_client: dict[str, dict[str, int]] = {}
    for r in rows:
        ip = _resolve_client_value(r["cid"], ipmap)
        if ip is None:
            continue
        c = per_client.setdefault(ip, {"baseline_nx": 0, "baseline_total": 0, "recent_nx": 0, "recent_total": 0})
        if r["is_recent"]:
            c["recent_nx"] += r["nx"]
            c["recent_total"] += r["total"]
        else:
            c["baseline_nx"] += r["nx"]
            c["baseline_total"] += r["total"]

    resolved = resolve.get_names()
    manual = names.get_names()
    anomalies: list[dict] = []
    for ip, c in per_client.items():
        if c["baseline_total"] < NXDOMAIN_MIN_BASELINE_COUNT or c["recent_total"] < NXDOMAIN_MIN_RECENT_COUNT:
            continue
        if c["recent_nx"] < NXDOMAIN_MIN_RECENT_NX:
            continue
        baseline_rate = c["baseline_nx"] / c["baseline_total"]
        recent_rate = c["recent_nx"] / c["recent_total"]
        threshold = max(baseline_rate * NXDOMAIN_RATE_MULTIPLIER, NXDOMAIN_MIN_FLOOR_RATE)
        if recent_rate <= threshold:
            continue
        name = _display_name(namemap.get(ip), ip, resolved, manual)
        anomalies.append({
            "ip": ip, "name": name, "kind": "nxdomain",
            "baseline_avg": round(baseline_rate * 100, 1),
            "baseline_stddev": 0.0,  # not applicable to a rate metric
            "current_value": round(recent_rate * 100, 1),
            "window_since": recent_start, "window_until": now,
        })
    return anomalies


# Shared presence qualifier for "this client went quiet" events (#6/#7),
# consumed by both alerts.py's device_quiet rule and detect_anomalies()'s
# "silent" case so the two surfaces never disagree about the same client.
# No active network probing (see #7) — DNS Watch's container has no LAN-layer
# visibility (default Docker bridge networking), so this labels honestly
# from data already on hand instead of guessing reachability.
PRESENCE_MAC_KNOWN_NOTE = (
    "may be offline, or may have switched to a different DNS resolver "
    "(DoH, VPN, hardcoded upstream)"
)
PRESENCE_MAC_UNKNOWN_NOTE = (
    "presence cannot be determined — DNS Watch never observed this device's "
    "hardware address"
)


def _read_dhcp_leases() -> dict[str, tuple[str, int]]:
    """mac (lowercase) -> (ip, expiry_epoch), parsed from dnsmasq's lease
    file at LEASES_PATH (#58) -- one line per lease:
    '<expiry-epoch> <mac> <ip> <hostname-or-*> <client-id-or-*>'.

    Returns {} when the file is missing, empty, or unreadable -- this is the
    common case when Pi-hole ISN'T the network's DHCP server (e.g. the
    router handles DHCP instead, confirmed to be the more common home-network
    topology by checking this project's own production instance), not an
    error. Silently degrading here is the same discipline the PTR
    reverse-DNS fallback already has, and NOT active presence probing (see
    #13's own scope-block) -- this only ever reads whatever Pi-hole's own
    dnsmasq already wrote to a file already inside the existing read-only
    mount, never touches the network itself.
    """
    try:
        with open(LEASES_PATH, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return {}
    leases: dict[str, tuple[str, int]] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            expiry = int(parts[0])
        except ValueError:
            continue
        leases[parts[1].lower()] = (parts[2], expiry)
    return leases


def _lease_confidence_note(ip: str, hwaddr: str | None) -> str | None:
    """A DHCP-lease-derived confidence annotation to append to `ip`'s quiet-
    presence note (#58), or None when unavailable/inapplicable. Requires a
    KNOWN hwaddr for this client (mac_known) as well as a lease record for
    that exact mac still pointing at this same ip -- a lease for a
    different ip means the mac has since moved (or DHCP reassigned this ip
    to someone else), which isn't a presence signal for the client being
    asked about."""
    if not hwaddr:
        return None
    lease = _read_dhcp_leases().get(hwaddr.lower())
    if lease is None or lease[0] != ip:
        return None
    _, expiry = lease
    now = int(time.time())
    if expiry <= now:
        age_h = (now - expiry) // 3600
        return f"its DHCP lease expired {age_h}h ago"
    return "its DHCP lease is still active (the device may simply be idle)"


def quiet_presence_note(ip: str) -> str:
    """The qualifier to append to a "client went quiet" message/event for `ip`."""
    with _connect() as conn:
        fields = _vendor_fields(ip, _client_vendor_map(conn))
    mac_known = fields["mac_known"]
    base = PRESENCE_MAC_KNOWN_NOTE if mac_known else PRESENCE_MAC_UNKNOWN_NOTE
    lease_note = _lease_confidence_note(ip, fields["hwaddr"]) if mac_known else None
    return f"{base} — {lease_note}" if lease_note else base


def health() -> dict:
    try:
        with _connect() as conn:
            conn.execute("SELECT 1 FROM queries LIMIT 1")
        return {"ok": True, "db_path": DB_PATH, "checked_at": int(time.time())}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "db_path": DB_PATH, "error": str(e)}
