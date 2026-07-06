"""Correctness tests for the incremental rollup cache (rollups.refresh_rollups).

Two layers:

  * Cross-schema smoke (`ftl` fixture, all four schema shapes): after a refresh
    from empty, the rollup totals must agree with db.summary()'s trusted
    whole-table aggregates -- proving the update function works regardless of
    which Pi-hole schema is active, including the old shapes with no integer
    ids at all.

  * Deep idstore correctness (own DB with the two proven traps): a
    duplicate-ip client (one ip under two client_by_id ids) and orphaned
    domain/client ids (referenced by query_storage, absent from the lookup
    tables). The trusted `queries` VIEW -- which resolves ids to text/NULL,
    merges dup-ip by resolved ip, and folds orphans to NULL -- is the oracle.
    Also exercises the cursor: refresh twice (with new rows between, then with
    nothing new) and confirm nothing is double-counted or skipped.
"""

from __future__ import annotations

import random
import sqlite3

import pytest

from conftest import _idstore_client_id, _idstore_domain_id, _idstore_schema, truth
from app import db, rollups


@pytest.fixture
def rstore(tmp_path, monkeypatch):
    """Point the rollup store at a throwaway file (never the real one)."""
    path = str(tmp_path / "dnswatch.db")
    monkeypatch.setattr(rollups, "STORE_PATH", path)
    return path


# --------------------------------------------------------------------------
# Cross-schema smoke: rollups agree with db.summary() on all four schemas.
# --------------------------------------------------------------------------


def _rollup_state(path: str) -> dict:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row

    def rows(sql):
        return conn.execute(sql).fetchall()

    state = {
        "domain": {r["domain"]: r["count"] for r in rows("SELECT * FROM domain_totals")},
        "client": {r["ip"]: dict(r) for r in rows("SELECT * FROM client_totals")},
        "qtype": {r["type"]: r["count"] for r in rows("SELECT * FROM query_type_totals")},
        "daily": {r["day"]: (r["allowed_count"], r["blocked_count"]) for r in rows("SELECT * FROM daily_totals")},
        "client_domain": {(r["ip"], r["domain"]): r["count"] for r in rows("SELECT * FROM client_domain_rollup")},
        "client_activity": {(r["ip"], r["day"]): r["count"] for r in rows("SELECT * FROM client_activity_rollup")},
        "cursor": dict(rows("SELECT * FROM rollup_cursor")[0]),
    }
    conn.close()
    return state


def test_refresh_matches_summary_all_schemas(ftl, rstore):
    """Whole-table aggregates the rollup precomputes must equal db.summary()'s
    trusted values, on every schema shape. (No orphans/dup-ips in this random
    fixture, so sums are exact, not just <=.)"""
    result = rollups.refresh_rollups()
    assert result["processed"] == 500  # build_ftl default n

    trusted = db.summary(None, None, None)
    st = _rollup_state(rstore)

    assert sum(st["qtype"].values()) == trusted["total_queries"]
    assert sum(st["domain"].values()) == trusted["total_queries"]
    assert sum(c["count"] for c in st["client"].values()) == trusted["total_queries"]
    assert len(st["domain"]) == trusted["unique_domains"]
    assert len(st["client"]) == trusted["unique_clients"]
    # allowed+blocked never exceeds total; equal here because the fixture's
    # STATUSES are all in the allowed/blocked sets (no "unknown").
    assert sum(a + b for a, b in st["daily"].values()) == trusted["total_queries"]


def test_refresh_noop_when_nothing_new(ftl, rstore):
    rollups.refresh_rollups()
    again = rollups.refresh_rollups()
    assert again == {"processed": 0, "batches": 0}


# --------------------------------------------------------------------------
# Deep idstore correctness: dup-ip merge + orphan exclusion, view as oracle.
# --------------------------------------------------------------------------

_CLIENTS = [
    ("192.168.0.10", "laptop"),
    ("192.168.0.11", "phone"),
    ("192.168.0.12", None),
]
_DUP_IP = "127.0.0.1"
_DOMAINS = [f"d{i:02d}.example.com" for i in range(12)]
_STATUSES = [2, 3, 1, 5, 2, 16, 3]  # allowed + blocked mix
_TYPES = [1, 2, 16, 6]
_ORPHAN_DOMAIN_IDS = [9001, 9002, 9003]  # never registered in domain_by_id
_ORPHAN_CLIENT_IDS = [9101, 9102]        # never registered in client_by_id
_NOW = 1_700_000_000


def _emit(c, n, ts_lo, ts_hi, did_pool, cid_pool):
    for _ in range(n):
        c.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (random.randint(ts_lo, ts_hi), random.choice(_TYPES),
             random.choice(_STATUSES), random.choice(did_pool), random.choice(cid_pool)),
        )


def _build_idstore_with_traps(path: str, ts_lo: int, ts_hi: int) -> None:
    """Normalized-layout DB with resolvable traffic, a duplicate-ip client
    (two ids, one ip), and rows referencing orphaned domain/client ids."""
    random.seed(1234)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)
    client_ids = [_idstore_client_id(c, ip, name) for ip, name in _CLIENTS]
    client_ids.append(_idstore_client_id(c, _DUP_IP, ""))          # dup id #1
    client_ids.append(_idstore_client_id(c, _DUP_IP, "localhost"))  # dup id #2, same ip
    domain_ids = [_idstore_domain_id(c, d) for d in _DOMAINS]

    _emit(c, 2000, ts_lo, ts_hi, domain_ids, client_ids)           # normal traffic
    for k, odid in enumerate(_ORPHAN_DOMAIN_IDS):                    # orphan domains
        _emit(c, 20 + 7 * k, ts_lo, ts_hi, [odid], client_ids)
    for k, ocid in enumerate(_ORPHAN_CLIENT_IDS):                    # orphan clients
        _emit(c, 15 + 5 * k, ts_lo, ts_hi, domain_ids, [ocid])
    _emit(c, 10, ts_lo, ts_hi, [_ORPHAN_DOMAIN_IDS[0]], [_ORPHAN_CLIENT_IDS[0]])  # both
    conn.commit()
    conn.close()


def _expected_from_view(path: str) -> dict:
    """Ground truth computed from the trusted `queries` VIEW: it resolves ids to
    text (orphans -> NULL) and exposes the client as its resolved ip (dup ids
    collapse to one ip). This is exactly the semantics refresh_rollups must
    reproduce with resolved-text keys, orphans excluded from keyed tables."""
    conn = truth(path)
    view_rows = conn.execute(
        "SELECT timestamp, type, status, domain, client AS ip FROM queries"
    ).fetchall()
    names = {r["ip"]: r["name"] for r in conn.execute("SELECT ip, name FROM network_addresses")}
    conn.close()

    from datetime import datetime, timezone

    def day(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")

    domain: dict = {}
    client: dict = {}
    qtype: dict = {}
    daily: dict = {}
    cd: dict = {}
    ca: dict = {}
    for r in view_rows:
        ts, typ, status, dom, ip = r["timestamp"], r["type"], r["status"], r["domain"], r["ip"]
        qtype[typ] = qtype.get(typ, 0) + 1
        d = daily.setdefault(day(ts), [0, 0])
        if status in db.BLOCKED_STATUSES:
            d[1] += 1
        elif status in db.ALLOWED_STATUSES:
            d[0] += 1
        if dom is not None:
            domain[dom] = domain.get(dom, 0) + 1
        if ip is not None:
            c = client.get(ip)
            if c is None:
                client[ip] = {"count": 1, "first_seen": ts, "last_seen": ts, "name": names.get(ip)}
            else:
                c["count"] += 1
                c["first_seen"] = min(c["first_seen"], ts)
                c["last_seen"] = max(c["last_seen"], ts)
            ca[(ip, day(ts))] = ca.get((ip, day(ts)), 0) + 1
            if dom is not None:
                cd[(ip, dom)] = cd.get((ip, dom), 0) + 1
    return {
        "domain": domain, "client": client, "qtype": qtype,
        "daily": {k: tuple(v) for k, v in daily.items()},
        "client_domain": cd, "client_activity": ca,
    }


def _assert_matches(state: dict, expected: dict) -> None:
    assert state["domain"] == expected["domain"]
    assert state["qtype"] == expected["qtype"]
    assert state["daily"] == expected["daily"]
    assert state["client_domain"] == expected["client_domain"]
    assert state["client_activity"] == expected["client_activity"]
    # client_totals: compare count/first_seen/last_seen/name per ip.
    assert set(state["client"]) == set(expected["client"])
    for ip, exp in expected["client"].items():
        got = state["client"][ip]
        assert got["count"] == exp["count"]
        assert got["first_seen"] == exp["first_seen"]
        assert got["last_seen"] == exp["last_seen"]
        assert got["name"] == exp["name"]


@pytest.fixture
def idb(tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    monkeypatch.setattr(db, "DB_PATH", path)
    db.detect_schema.cache_clear()
    yield path
    db.detect_schema.cache_clear()


def test_idstore_dupip_and_orphans_match_view(idb, rstore):
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    state = _rollup_state(rstore)
    expected = _expected_from_view(idb)
    _assert_matches(state, expected)

    # The traps are actually present (non-vacuous):
    # dup ip appears exactly once, merged.
    assert _DUP_IP in state["client"]
    # orphaned domains/clients excluded from keyed tables ...
    for oid in _ORPHAN_DOMAIN_IDS:
        assert oid not in state["domain"]  # ids never leak in as keys
    assert None not in state["domain"]
    assert None not in state["client"]
    # ... yet their rows were still counted in the type/day rollups.
    total_rows = 2000 + sum(20 + 7 * k for k in range(3)) + sum(15 + 5 * k for k in range(2)) + 10
    assert sum(state["qtype"].values()) == total_rows
    assert sum(a + b for a, b in state["daily"].values()) <= total_rows  # unknown-status excluded


def test_cursor_advances_no_double_count(idb, rstore):
    """Refresh, add more rows, refresh again: cumulative totals must equal a
    single refresh over ALL rows (nothing double-counted or skipped), and a
    final no-new-data refresh must be a no-op."""
    # First half of the data, in an older time window.
    _build_idstore_with_traps(idb, _NOW - 10 * 86400, _NOW - 6 * 86400)
    r1 = rollups.refresh_rollups()
    assert r1["processed"] > 0
    cur1 = _rollup_state(rstore)["cursor"]

    # Append MORE rows (newer timestamps, higher ids). Reuses the existing
    # lookup tables so resolved ips/domains overlap the first batch -> exercises
    # UPSERT increments, not just inserts.
    conn = sqlite3.connect(idb)
    c = conn.cursor()
    client_ids = [r[0] for r in c.execute("SELECT id FROM client_by_id").fetchall()]
    domain_ids = [r[0] for r in c.execute("SELECT id FROM domain_by_id").fetchall()]
    random.seed(555)
    _emit(c, 800, _NOW - 5 * 86400, _NOW, domain_ids, client_ids)
    conn.commit()
    conn.close()

    r2 = rollups.refresh_rollups()
    assert r2["processed"] == 800
    cur2 = _rollup_state(rstore)["cursor"]
    assert cur2["last_query_id"] > cur1["last_query_id"]

    # No-op third call.
    assert rollups.refresh_rollups() == {"processed": 0, "batches": 0}

    incremental = _rollup_state(rstore)

    # The incrementally-built rollup (two refreshes across two data batches)
    # must equal ground truth computed in one shot from the trusted view over
    # ALL current rows -- proving the first batch was neither re-counted nor
    # lost when the second batch's UPSERTs incremented the same keys.
    _assert_matches(incremental, _expected_from_view(idb))


def test_small_batch_size_drains_completely(idb, rstore):
    """A batch_size smaller than the row count must still process every row via
    the keyset loop and land on the same result as one big batch."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    res = rollups.refresh_rollups(batch_size=137)
    assert res["batches"] > 1
    _assert_matches(_rollup_state(rstore), _expected_from_view(idb))


# --------------------------------------------------------------------------
# Reconciliation: the drift-and-correct property.
#
# refresh_rollups only ever ADDS rows above its cursor, so when Pi-hole prunes
# old rows on its retention schedule the rollup totals drift upward and refresh
# alone can never pull them back down. reconcile_rollups rebuilds from scratch
# and erases that drift. These tests prove the drift is real (not accidentally
# already handled) AND that reconciliation removes it exactly.
# --------------------------------------------------------------------------


def _remaining_row_count(path: str) -> int:
    conn = sqlite3.connect(path)
    n = conn.execute("SELECT COUNT(*) FROM query_storage").fetchone()[0]
    conn.close()
    return n


def test_reconcile_corrects_pruning_drift(idb, rstore):
    """Build a rollup, prune old rows from Pi-hole's underlying table, prove
    refresh_rollups does NOT correct the pruned rows' contribution (drift is
    real), then prove reconcile_rollups(force=True) rebuilds to exactly match a
    fresh full computation over the now-smaller dataset."""
    _build_idstore_with_traps(idb, _NOW - 10 * 86400, _NOW)
    rollups.refresh_rollups()

    before = _rollup_state(rstore)
    full_before = _expected_from_view(idb)
    _assert_matches(before, full_before)  # sanity: rollup == full data initially

    # Simulate Pi-hole's maxDBdays retention pruning: delete the oldest rows.
    cutoff = _NOW - 6 * 86400
    conn = sqlite3.connect(idb)
    deleted = conn.execute(
        "DELETE FROM query_storage WHERE timestamp < ?", (cutoff,)
    ).rowcount
    conn.commit()
    conn.close()
    assert deleted > 0  # the prune actually removed rows

    # refresh_rollups alone is a NO-OP here: the deleted rows are all BELOW the
    # cursor's high-water mark, and refresh only reads rows above it. So the
    # rollup keeps counting rows that no longer exist -- the drift.
    assert rollups.refresh_rollups() == {"processed": 0, "batches": 0}

    drifted = _rollup_state(rstore)
    full_after = _expected_from_view(idb)

    # The drifted rollup still holds the PRE-prune totals ...
    assert sum(drifted["qtype"].values()) == sum(before["qtype"].values())
    # ... which are strictly larger than the current (pruned) reality ...
    assert sum(drifted["qtype"].values()) > sum(full_after["qtype"].values())
    assert sum(drifted["qtype"].values()) - sum(full_after["qtype"].values()) == deleted
    # ... i.e. the rollup no longer matches the actual dataset (drift confirmed).
    with pytest.raises(AssertionError):
        _assert_matches(drifted, full_after)

    # Reconcile: rebuild from scratch and re-drain the (smaller) table.
    res = rollups.reconcile_rollups(force=True)
    assert res["reconciled"] is True
    assert res["processed"] == _remaining_row_count(idb)
    assert res["batches"] >= 1

    # Drift is gone: the rollup now matches a fresh full computation exactly,
    # across every table (totals, per-domain, per-client, daily, cross rollups).
    _assert_matches(_rollup_state(rstore), full_after)


def test_reconcile_interval_gating_and_force(idb, rstore):
    """No-op inside the interval, forced past it, and unset == 'never
    reconciled, do it now'."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)

    # Never reconciled -> the first (unforced, default-interval) call runs.
    first = rollups.reconcile_rollups()
    assert first["reconciled"] is True
    assert first["processed"] == _remaining_row_count(idb)

    # Immediately again, well within the default 1-day interval -> no-op.
    again = rollups.reconcile_rollups()
    assert again["reconciled"] is False
    assert "seconds_until_due" in again

    # force=True bypasses the interval check entirely.
    forced = rollups.reconcile_rollups(force=True)
    assert forced["reconciled"] is True

    # interval_seconds=0 -> the interval has always "elapsed" -> runs.
    assert rollups.reconcile_rollups(interval_seconds=0)["reconciled"] is True


def test_first_boot_refresh_does_not_trigger_immediate_reconcile(ftl, rstore):
    """#3: a from-scratch refresh_rollups() (true first boot, cursor never
    initialized) must stamp last_reconciled_at itself, so the very next
    reconcile_rollups() call in the same scheduler tick sees a fresh stamp and
    no-ops instead of immediately redoing the exact same full backfill."""
    first = rollups.refresh_rollups()
    assert first["processed"] > 0  # the ftl fixture always has queries

    conn = sqlite3.connect(rstore)
    conn.row_factory = sqlite3.Row
    meta = conn.execute("SELECT last_reconciled_at FROM rollup_meta WHERE id = 1").fetchone()
    conn.close()
    assert meta["last_reconciled_at"] is not None

    # Same tick, immediately after: must be a no-op, not a second full backfill.
    again = rollups.reconcile_rollups()
    assert again["reconciled"] is False
    assert "seconds_until_due" in again


def test_reconcile_matches_a_from_empty_refresh(idb, rstore):
    """A forced reconcile with no pruning must land on the identical state a
    single from-empty refresh_rollups produces -- confirming reconcile reuses
    the same drain rather than a divergent rebuild path."""
    _build_idstore_with_traps(idb, _NOW - 5 * 86400, _NOW)
    rollups.refresh_rollups()
    baseline = _rollup_state(rstore)

    res = rollups.reconcile_rollups(force=True)
    assert res["reconciled"] is True

    after = _rollup_state(rstore)
    # Cursor differs only in identity of the row; the aggregates must be identical.
    for key in ("domain", "qtype", "daily", "client_domain", "client_activity"):
        assert after[key] == baseline[key]
    assert after["client"] == baseline["client"]
