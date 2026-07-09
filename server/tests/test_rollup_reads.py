"""Correctness tests for the rollup-backed READ paths (rollups.read_*).

A rollup read is now a THIRD implementation of these aggregates, alongside the
`queries`-view path and the direct-id path. All three must agree. These tests
prove:

  * Three-way agreement on the idstore layout WITH the two known traps
    (duplicate-ip client, orphaned domain/client ids): rollups.read_* ==
    db._*_id (the direct-id oracle, which test_id_aggregates.py already pins to
    the view). The orphan traps matter specially here because the rollup keyed
    tables EXCLUDE orphans, so the read path must RECONSTRUCT the direct path's
    single collapsed {None} group by arithmetic -- a naive read would drop it.

  * Cross-schema agreement (all four schema shapes via the `ftl` fixture):
    rollups.read_* == db.<fn> with the rollup dispatch forced off, so the read
    path is proven correct on the old/new/real layouts too, not just idstore.

  * The staleness boundary is honest: a read immediately after new data lands
    (before the next tick) legitimately lags; calling refresh_rollups() -- the
    guarantee this design actually makes -- brings it back in sync.

  * A never-backfilled rollup (cursor NULL) returns None so db.py falls through
    to the correct-but-slow direct scan, rather than serving empty tables.

  * Bounded ranges NEVER touch the rollup path (spy on the read functions).
"""

from __future__ import annotations

import random
import sqlite3

import pytest

from conftest import _idstore_client_id, _idstore_domain_id, _idstore_schema
from app import db, names, resolve, rollups


# --------------------------------------------------------------------------
# Fixtures: throwaway rollup store + throwaway Pi-hole FTL db.
# --------------------------------------------------------------------------


@pytest.fixture
def rstore(tmp_path, monkeypatch):
    path = str(tmp_path / "dnswatch.db")
    monkeypatch.setattr(rollups, "STORE_PATH", path)
    return path


@pytest.fixture
def idb(tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    monkeypatch.setattr(db, "DB_PATH", path)
    db.detect_schema.cache_clear()
    yield path
    db.detect_schema.cache_clear()


# --------------------------------------------------------------------------
# idstore dataset with the two proven traps (mirrors test_id_aggregates.py).
# --------------------------------------------------------------------------

_CLIENTS = [
    ("192.168.0.10", "laptop"),
    ("192.168.0.11", "phone"),
    ("192.168.0.12", None),
]
_DUP_IP = "127.0.0.1"
_DOMAINS = [f"d{i:02d}.example.com" for i in range(12)]
_STATUSES = [2, 3, 1, 5, 2, 16, 3, 99]  # allowed + blocked + one "unknown" (99)
_TYPES = [1, 2, 16, 6]
_ORPHAN_DOMAIN_IDS = [9001, 9002, 9003]
_ORPHAN_CLIENT_IDS = [9101, 9102]
_NOW = 1_700_000_000


def _emit(c, n, ts_lo, ts_hi, did_pool, cid_pool):
    for _ in range(n):
        c.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (random.randint(ts_lo, ts_hi), random.choice(_TYPES),
             random.choice(_STATUSES), random.choice(did_pool), random.choice(cid_pool)),
        )


def _build_idstore_with_traps(path: str, ts_lo: int, ts_hi: int) -> None:
    random.seed(1234)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)
    client_ids = [_idstore_client_id(c, ip, name) for ip, name in _CLIENTS]
    client_ids.append(_idstore_client_id(c, _DUP_IP, ""))
    client_ids.append(_idstore_client_id(c, _DUP_IP, "localhost"))
    domain_ids = [_idstore_domain_id(c, d) for d in _DOMAINS]

    _emit(c, 2000, ts_lo, ts_hi, domain_ids, client_ids)
    for k, odid in enumerate(_ORPHAN_DOMAIN_IDS):
        _emit(c, 20 + 7 * k, ts_lo, ts_hi, [odid], client_ids)
    for k, ocid in enumerate(_ORPHAN_CLIENT_IDS):
        _emit(c, 15 + 5 * k, ts_lo, ts_hi, domain_ids, [ocid])
    _emit(c, 10, ts_lo, ts_hi, [_ORPHAN_DOMAIN_IDS[0]], [_ORPHAN_CLIENT_IDS[0]])
    conn.commit()
    conn.close()


def _append_rows(path: str, n: int, ts_lo: int, ts_hi: int) -> None:
    """More resolvable traffic reusing existing lookup tables (exercises the read
    path after an incremental refresh, and gives the staleness test new data)."""
    conn = sqlite3.connect(path)
    c = conn.cursor()
    client_ids = [r[0] for r in c.execute("SELECT id FROM client_by_id").fetchall()]
    domain_ids = [r[0] for r in c.execute("SELECT id FROM domain_by_id").fetchall()]
    random.seed(777)
    _emit(c, n, ts_lo, ts_hi, domain_ids, client_ids)
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Tie-robust comparators (SQL ORDER BY is unordered among equal counts, so the
# three paths need not agree on tie ordering -- only on the multiset of results).
# --------------------------------------------------------------------------


def _n(v):
    """Sort key that tolerates None (orphan groups) alongside strings."""
    return (v is None, v)


def _domain_map(rows):
    # A LIST of (domain, count) so multiple None rows can't be silently merged.
    return sorted(((r["domain"], r["count"]) for r in rows), key=lambda t: (_n(t[0]), t[1]))


def _client_map(rows):
    return sorted(
        ((r["ip"], r["name"], r["count"]) for r in rows),
        key=lambda t: (_n(t[0]), _n(t[1]), t[2]),
    )


def _type_map(rows):
    return sorted(((r["type_code"], r["count"]) for r in rows), key=lambda t: (t[0], t[1]))


# --------------------------------------------------------------------------
# Three-way agreement on idstore with traps: read_* == direct-id oracle.
# --------------------------------------------------------------------------


def test_read_summary_matches_direct_idstore(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    assert rollups.read_summary() == db._summary_id(None, None, None)


def test_read_top_domains_matches_direct_idstore(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    for lim in (1, 5, 15, 1000):
        got = rollups.read_top_domains(None, lim)
        exp = db._top_domains_id(None, None, lim)
        # Count sequence proves identical ranking + the merged orphan group's
        # placement; the full map proves the exact multiset.
        assert [r["count"] for r in got] == [r["count"] for r in exp]
        assert _domain_map(got) == _domain_map(exp)
    # The orphan group really is present (non-vacuous) at full ranking.
    full = rollups.read_top_domains(None, 1000)
    assert [r["domain"] for r in full].count(None) == 1


def test_read_top_domains_client_filter_matches_direct_idstore(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    # The duplicate-ip client (its per-domain counts come from client_domain_rollup).
    for ip in (_DUP_IP, "192.168.0.10"):
        got = rollups.read_top_domains(ip, 1000)
        exp = db._top_domains_id(ip, None, 1000)
        assert _domain_map(got) == _domain_map(exp)
    # An unknown ip: both yield [].
    assert rollups.read_top_domains("10.0.0.254", 15) == db._top_domains_id("10.0.0.254", None, 15) == []


def test_read_top_clients_matches_direct_idstore(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    for lim in (1, 3, 1000):
        got = rollups.read_top_clients(lim)
        exp = db._top_clients_id(None, lim)
        assert [r["count"] for r in got] == [r["count"] for r in exp]
        assert _client_map(got) == _client_map(exp)
    full = rollups.read_top_clients(1000)
    # Dup ip merged to one row; orphan clients folded into one None row.
    assert [r["ip"] for r in full].count(_DUP_IP) == 1
    assert [r["ip"] for r in full].count(None) == 1


def test_read_top_clients_applies_manual_and_resolved_names(idb, rstore, monkeypatch):
    """Regression: read_top_clients() used to serve client_totals.name (Pi-hole's
    own name) or the bare ip directly, unlike every direct-scan path -- which
    layers a manual override (names.py) and DNS Watch's own reverse-DNS cache
    (resolve.py) on top via db._display_name. A client renamed by hand, or
    resolved via PTR, must show that friendly name on the All-time view too,
    not just on bounded ranges."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()

    manually_named_ip = _CLIENTS[2][0]  # ("192.168.0.12", None) -- Pi-hole never named this one
    names.set_name(manually_named_ip, "My Fridge")

    # Also give it a (stubbed) successful PTR resolution, to prove the manual
    # override still wins over that too -- same precedence db._display_name
    # enforces on every other path.
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "desktop.lan")
    resolve.resolve_batch([manually_named_ip])

    got = {r["ip"]: r["name"] for r in rollups.read_top_clients(1000)}
    # Manual override wins even over a (stubbed) successful PTR resolution.
    assert got[manually_named_ip] == "My Fridge"


def test_read_client_activity_applies_manual_and_resolved_names(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()

    manually_named_ip = _CLIENTS[2][0]
    names.set_name(manually_named_ip, "My Fridge")

    got = {r["ip"]: r["name"] for r in rollups.read_client_activity(1000)}
    assert got[manually_named_ip] == "My Fridge"


def test_read_query_types_matches_direct_idstore(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    got = rollups.read_query_types()
    exp = db._query_types_id(None, None, None)
    assert _type_map(got) == _type_map(exp)
    assert [r["count"] for r in got] == [r["count"] for r in exp]


def test_new_domains_matches_ground_truth(idb, rstore):
    """#32: rollups.new_domains() is a persisted first-seen-per-domain table
    maintained incrementally (see the module note on _Deltas.domain_first_seen/
    _apply), not a live scan -- verified against a raw MIN(timestamp) GROUP BY
    domain query over the real query_storage rows."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()

    conn = sqlite3.connect(idb)
    conn.row_factory = sqlite3.Row
    truth = {
        r["domain"]: r["fs"]
        for r in conn.execute(
            "SELECT d.domain AS domain, MIN(q.timestamp) AS fs "
            "FROM query_storage q JOIN domain_by_id d ON d.id = q.domain "
            "GROUP BY d.domain"
        )
    }

    # A cutoff strictly before the earliest of anything -> every domain is "new".
    all_new = {r["domain"]: r["first_seen"] for r in rollups.new_domains(0)}
    assert all_new == {d: int(ts) for d, ts in truth.items()}

    # A cutoff after everything -> nothing is new.
    assert rollups.new_domains(_NOW + 1) == []

    # A cutoff in the middle -> exactly the domains first seen at/after it.
    cutoff = _NOW - 2 * 86400
    expected_mid = {d for d, ts in truth.items() if ts >= cutoff}
    got_mid = {r["domain"] for r in rollups.new_domains(cutoff)}
    assert got_mid == expected_mid


def test_new_domains_reflects_a_genuinely_new_domain_after_refresh(idb, rstore):
    """A domain inserted AFTER the initial backfill, then picked up by a
    second refresh_rollups() call, must show up as first-seen at its own
    (later) timestamp -- not silently missing, and not misdated to the
    original dataset's time range."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    before = {r["domain"] for r in rollups.new_domains(0)}
    assert "brand-new.example" not in before

    conn = sqlite3.connect(idb)
    c = conn.cursor()
    did = _idstore_domain_id(c, "brand-new.example")
    cid = _idstore_client_id(c, "192.168.0.10", "laptop")
    later = _NOW + 1000
    c.execute(
        "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
        (later, 1, 2, did, cid),
    )
    conn.commit()
    conn.close()

    rollups.refresh_rollups()
    after = {r["domain"]: r["first_seen"] for r in rollups.new_domains(0)}
    assert after["brand-new.example"] == later


# --------------------------------------------------------------------------
# Cross-schema agreement: read_* == the direct scan on every schema shape.
#
# db.<fn> normally dispatches to the rollup read for the All range, so to get the
# DIRECT result we temporarily stub the specific read function to return None
# (its "can't serve -> fall through" signal), call the function, then restore and
# call again for the rollup result. Both share one identical dataset.
# --------------------------------------------------------------------------


def _direct_then_rollup(monkeypatch, read_name, fn):
    orig = getattr(rollups, read_name)
    monkeypatch.setattr(rollups, read_name, lambda *a, **k: None)
    direct = fn()
    monkeypatch.setattr(rollups, read_name, orig)
    served = fn()
    return direct, served


def test_read_summary_matches_all_schemas(ftl, rstore, monkeypatch):
    rollups.refresh_rollups()
    direct, served = _direct_then_rollup(
        monkeypatch, "read_summary", lambda: db.summary(None, None, None)
    )
    assert served == direct


def test_read_top_domains_matches_all_schemas(ftl, rstore, monkeypatch):
    rollups.refresh_rollups()
    direct, served = _direct_then_rollup(
        monkeypatch, "read_top_domains", lambda: db.top_domains(None, None, 1000)
    )
    assert _domain_map(served) == _domain_map(direct)


def test_read_top_clients_matches_all_schemas(ftl, rstore, monkeypatch):
    rollups.refresh_rollups()
    direct, served = _direct_then_rollup(
        monkeypatch, "read_top_clients", lambda: db.top_clients(None, 1000)
    )
    assert _client_map(served) == _client_map(direct)


def test_read_query_types_matches_all_schemas(ftl, rstore, monkeypatch):
    rollups.refresh_rollups()
    direct, served = _direct_then_rollup(
        monkeypatch, "read_query_types", lambda: db.query_types(None, None, None)
    )
    assert _type_map(served) == _type_map(direct)


# --------------------------------------------------------------------------
# Incremental refresh: reading after a second batch still matches the direct
# scan over ALL rows (nothing double-counted or dropped by the read arithmetic).
# --------------------------------------------------------------------------


def test_read_matches_direct_after_incremental_refresh(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 10 * 86400, _NOW - 6 * 86400)
    rollups.refresh_rollups()
    _append_rows(idb, 800, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()

    assert rollups.read_summary() == db._summary_id(None, None, None)
    assert _domain_map(rollups.read_top_domains(None, 1000)) == _domain_map(
        db._top_domains_id(None, None, 1000)
    )
    assert _client_map(rollups.read_top_clients(1000)) == _client_map(
        db._top_clients_id(None, 1000)
    )
    assert _type_map(rollups.read_query_types()) == _type_map(
        db._query_types_id(None, None, None)
    )


# --------------------------------------------------------------------------
# Staleness boundary: reads lag by design until the next refresh, and refresh
# (the design's actual guarantee) restores agreement with the direct scan.
# --------------------------------------------------------------------------


def test_read_lags_until_refresh_then_resyncs(idb, rstore):
    # Initial data sits in an OLDER window; the appended batch is strictly newer,
    # exactly as Pi-hole appends in time order (the refresh cursor is a
    # (timestamp, id) keyset, so a real append is always above the high-water mark).
    _build_idstore_with_traps(idb, _NOW - 10 * 86400, _NOW - 5 * 86400)
    rollups.refresh_rollups()
    before = rollups.read_summary()

    # New data lands but the scheduler tick hasn't run yet.
    _append_rows(idb, 500, _NOW - 4 * 86400, _NOW)

    # The direct scan already sees it; the rollup read legitimately does NOT.
    assert db._summary_id(None, None, None)["total_queries"] > before["total_queries"]
    assert rollups.read_summary() == before  # stale-by-design, not real-time

    # The tick runs: refresh is the guarantee, and it restores agreement.
    rollups.refresh_rollups()
    after = rollups.read_summary()
    assert after["total_queries"] > before["total_queries"]
    assert after == db._summary_id(None, None, None)


# --------------------------------------------------------------------------
# Never-backfilled rollup: reads signal "fall through", db.py returns direct.
# --------------------------------------------------------------------------


def test_unbackfilled_rollup_falls_through(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.init_rollup_store()  # tables exist, but cursor never advanced

    # Every read signals "not ready".
    assert rollups.read_summary() is None
    assert rollups.read_top_domains(None, 15) is None
    assert rollups.read_top_domains(_DUP_IP, 15) is None
    assert rollups.read_top_clients(15) is None
    assert rollups.read_query_types() is None
    assert rollups.new_domains(0) is None  # #32 -- see its own docstring on why

    # So db.py serves the correct direct result for the All range, never zeros.
    assert db.summary(None, None, None) == db._summary_id(None, None, None)
    assert db.summary(None, None, None)["total_queries"] > 0
    assert _domain_map(db.top_domains(None, None, 1000)) == _domain_map(
        db._top_domains_id(None, None, 1000)
    )
    assert _client_map(db.top_clients(None, 1000)) == _client_map(
        db._top_clients_id(None, 1000)
    )
    assert _type_map(db.query_types(None, None, None)) == _type_map(
        db._query_types_id(None, None, None)
    )


def test_mid_reconcile_falls_through_instead_of_serving_partial_data(idb, rstore):
    """Regression test: reconcile_rollups() truncates every rollup table and
    rewinds the cursor to NULL, then re-drains the whole table batch by batch.
    The cursor goes non-NULL again after just the FIRST batch commits -- long
    before the tables reflect the whole history again. A reader gating only on
    "cursor is non-NULL" would see a fully-backfilled rollup mid-rebuild and
    serve wildly undercounted totals instead of falling through to the
    correct-but-slow direct scan. Simulates that window directly (rather than
    racing threads against a real multi-batch rebuild) by fully backfilling,
    then raising the reconcile_in_progress flag the same way reconcile_rollups()
    does for the duration of its rebuild."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    assert rollups.read_summary() is not None  # fully backfilled, ready

    conn = sqlite3.connect(rstore)
    conn.execute("UPDATE rollup_meta SET reconcile_in_progress = 1 WHERE id = 1")
    conn.commit()
    conn.close()

    # Every read must signal "not ready" while a rebuild is in flight, exactly
    # like the never-backfilled case -- NOT serve the stale/partial tables.
    assert rollups.read_summary() is None
    assert rollups.read_top_domains(None, 15) is None
    assert rollups.read_top_domains(_DUP_IP, 15) is None
    assert rollups.read_top_clients(15) is None
    assert rollups.read_query_types() is None

    # So db.py still serves the correct direct result for the All range.
    assert db.summary(None, None, None) == db._summary_id(None, None, None)
    assert db.summary(None, None, None)["total_queries"] > 0


# --------------------------------------------------------------------------
# Bounded ranges must NEVER touch the rollup cache (it only serves the All
# range). Spy on every read function and assert none fire for a bounded call --
# nor for the cases that fall through by design (client-filtered summary/types).
# --------------------------------------------------------------------------


def test_bounded_range_never_reads_rollup(idb, rstore, monkeypatch):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()

    fired: list[str] = []

    def spy(name):
        def _f(*a, **k):
            fired.append(name)
            return None
        return _f

    for name in ("read_summary", "read_top_domains", "read_top_clients", "read_query_types"):
        monkeypatch.setattr(rollups, name, spy(name))

    since = _NOW - 3600
    # Bounded (since set): none of these may consult the rollup.
    db.summary(None, since, None)
    db.top_domains(None, since, 15)
    db.top_clients(since, 15)
    db.query_types(None, since, None)
    assert fired == []

    # Unbounded but not rollup-servable (client filter / until bound): also must
    # not consult the rollup read for summary/query_types.
    db.summary(_DUP_IP, None, None)
    db.summary(None, None, _NOW)
    db.query_types(_DUP_IP, None, None)
    db.query_types(None, None, _NOW)
    assert fired == []

    # Sanity: the servable All-range calls DO consult the rollup (spy fires),
    # proving the empty `fired` above is real, not a wiring accident.
    db.summary(None, None, None)
    db.top_domains(None, None, 15)
    db.top_clients(None, 15)
    db.query_types(None, None, None)
    assert set(fired) == {"read_summary", "read_top_domains", "read_top_clients", "read_query_types"}
