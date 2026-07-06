"""Correctness regression for the id-based aggregate fast path.

Every aggregate rewritten to group/filter on `query_storage`'s raw integer
domain/client ids (Schema.has_id_storage) MUST return byte-for-byte the same
result as the trusted, pre-existing VIEW-based path on identical data. The
view-based path is the baseline; a fast-but-wrong rewrite is worse than the
slow-but-correct original.

Each test builds ONE normalized-layout database and runs the same function
twice against it — once with the fast path forced OFF (the `queries` view,
correlated-subquery path) and once forced ON (the raw-id path) — then asserts
the two outputs are identical. The database deliberately includes a client
whose ip (127.0.0.1) resolves to TWO distinct client_by_id ids, so the
group-by-id-then-merge-by-ip logic is genuinely exercised: a naive rewrite
that grouped by raw id would split that client in two and fail here.
"""

from __future__ import annotations

import random
import sqlite3

import pytest

from conftest import (
    _idstore_client_id,
    _idstore_domain_id,
    _idstore_schema,
    truth,
)
from app import db
from app.db import Schema


# Clients: four normal LAN devices plus 127.0.0.1 registered under TWO names,
# i.e. two client_by_id ids sharing one ip -> the merge-by-ip case.
_CLIENTS = [
    ("192.168.0.10", "laptop"),
    ("192.168.0.11", "phone"),
    ("192.168.0.12", "tv"),
    ("192.168.0.13", None),  # unnamed -> falls back to ip
]
_DUP_IP = "127.0.0.1"
_DOMAINS = [f"d{i:02d}.example.com" for i in range(20)]
_STATUSES = [2, 3, 1, 5, 2, 2, 3, 16]  # mix of allowed/blocked
_TYPES = [1, 2, 16, 6]


def _build(path: str) -> None:
    """A rich normalized-layout DB: many domains/clients, a ~10-day span, the
    duplicate-ip client, plus two clients with deliberate hourly patterns so
    detect_anomalies has a silent and a spiking device to find."""
    random.seed(1234)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)

    now = 1_700_000_000  # fixed epoch so nothing depends on wall clock here
    std_ids = [_idstore_client_id(c, ip, name) for ip, name in _CLIENTS]
    dup_a = _idstore_client_id(c, _DUP_IP, "")          # first identity
    dup_b = _idstore_client_id(c, _DUP_IP, "localhost")  # second identity, same ip
    all_ids = std_ids + [dup_a, dup_b]

    # Spread ~6000 rows across 10 days, all clients and domains.
    span = 10 * 86400
    for _ in range(6000):
        cid = random.choice(all_ids)
        did = _idstore_domain_id(c, random.choice(_DOMAINS))
        ts = now - random.randint(0, span)
        c.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (ts, random.choice(_TYPES), random.choice(_STATUSES), did, cid),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def idb(tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    _build(path)
    monkeypatch.setattr(db, "DB_PATH", path)
    return path


def _force(monkeypatch, has_id_storage: bool) -> None:
    """Pin detect_schema to the real detected shape for this layout
    (view-based, name on network_addresses) with only has_id_storage toggled,
    so both runs differ ONLY in which aggregate path executes."""
    schema = Schema(has_client_table=False, na_has_name=True, has_id_storage=has_id_storage)
    monkeypatch.setattr(db, "detect_schema", lambda: schema)


def _both(monkeypatch, fn):
    """Return (view_path_result, id_path_result) for a zero-arg callable."""
    _force(monkeypatch, False)
    view = fn()
    _force(monkeypatch, True)
    idp = fn()
    return view, idp


# --------------------------------------------------------------------------


def test_top_domains_matches(idb, monkeypatch):
    # Full ranking (limit past the distinct-domain count) makes the comparison
    # order- and tie-independent: identical {domain: count} maps prove it.
    view, idp = _both(monkeypatch, lambda: db.top_domains(None, None, limit=1000))
    assert {r["domain"]: r["count"] for r in view} == {r["domain"]: r["count"] for r in idp}
    assert None not in {r["domain"] for r in idp}  # every id resolved to text
    # Default top-15 counts sequence must match too (tie-robust: equal counts).
    v15, i15 = _both(monkeypatch, lambda: db.top_domains(None, None, limit=15))
    assert [r["count"] for r in v15] == [r["count"] for r in i15]


def test_top_domains_client_filter_matches(idb, monkeypatch):
    # Filter by the duplicate-ip client: both client_by_id ids must be included.
    view, idp = _both(monkeypatch, lambda: db.top_domains(_DUP_IP, None, limit=1000))
    assert {r["domain"]: r["count"] for r in view} == {r["domain"]: r["count"] for r in idp}
    # And a normal client.
    view2, idp2 = _both(monkeypatch, lambda: db.top_domains("192.168.0.10", None, limit=1000))
    assert {r["domain"]: r["count"] for r in view2} == {r["domain"]: r["count"] for r in idp2}


def test_top_domains_unknown_client_empty(idb, monkeypatch):
    view, idp = _both(monkeypatch, lambda: db.top_domains("10.0.0.254", None, limit=15))
    assert view == idp == []


def test_top_clients_matches(idb, monkeypatch):
    # Full ranking so ties don't matter; the duplicate-ip client must appear
    # ONCE with its two ids' counts merged (a naive raw-id group would show 2).
    view, idp = _both(monkeypatch, lambda: db.top_clients(None, limit=1000))
    vm = {r["ip"]: (r["count"], r["name"]) for r in view}
    im = {r["ip"]: (r["count"], r["name"]) for r in idp}
    assert vm == im
    assert _DUP_IP in im  # 127.0.0.1 present as a single merged row
    # Default top-15 counts sequence matches too.
    v15, i15 = _both(monkeypatch, lambda: db.top_clients(None, limit=15))
    assert [r["count"] for r in v15] == [r["count"] for r in i15]


def test_query_types_matches(idb, monkeypatch):
    view, idp = _both(monkeypatch, lambda: db.query_types(None, None, None))
    assert view == idp
    # With a client filter (the duplicate-ip client).
    v2, i2 = _both(monkeypatch, lambda: db.query_types(_DUP_IP, None, None))
    assert v2 == i2


def test_timeseries_matches(idb, monkeypatch):
    # Pin `until` so the two sequential calls share an identical window: with
    # until=None each call re-reads int(time.time()) and can land in a
    # different second, changing the bucket width for reasons unrelated to the
    # path under test. (`since=None` still exercises the MIN-derived window.)
    view, idp = _both(monkeypatch, lambda: db.timeseries(None, None, 1_700_000_100, buckets=50))
    assert view == idp
    # Bounded window + client filter.
    v2, i2 = _both(
        monkeypatch,
        lambda: db.timeseries("192.168.0.10", 1_699_500_000, 1_700_000_000, buckets=40),
    )
    assert v2 == i2


def test_summary_matches(idb, monkeypatch):
    view, idp = _both(monkeypatch, lambda: db.summary(None, None, None))
    assert view == idp
    # unique_clients must dedupe the duplicate ip: filtering on it yields 1.
    v2, i2 = _both(monkeypatch, lambda: db.summary(_DUP_IP, None, None))
    assert v2 == i2
    assert i2["unique_clients"] == 1


def test_client_activity_matches(idb, monkeypatch):
    # Pin `until` (client_activity re-reads time.time() when until is None,
    # which would differ between the two sequential calls).
    def call():
        return db.client_activity(None, 1_700_000_100, limit=100, buckets=20)

    view, idp = _both(monkeypatch, call)
    # Compare order-independently by ip; every field must match, including the
    # merged duplicate-ip client's summed count/sparkline.
    vm = {c["ip"]: c for c in view}
    im = {c["ip"]: c for c in idp}
    assert vm.keys() == im.keys()
    for ip in vm:
        assert vm[ip] == im[ip]
    assert _DUP_IP in im


def test_new_clients_matches(idb, monkeypatch):
    # A cutoff old enough to catch every client on this 10-day dataset.
    cutoff = 1_700_000_000 - 20 * 86400
    view, idp = _both(monkeypatch, lambda: db.new_clients(cutoff))
    vm = {c["ip"]: (c["first_seen"], c["total"], c["name"]) for c in view}
    im = {c["ip"]: (c["first_seen"], c["total"], c["name"]) for c in idp}
    assert vm == im
    # first_seen ordering (desc) agrees where values are distinct.
    assert [c["first_seen"] for c in view] == [c["first_seen"] for c in idp]


_ANOMALY_NOW = 1_800_000_000  # fixed clock so the test never depends on wall time


def _build_anomaly_db(path: str) -> None:
    """Normalized-layout DB with real >24h baselines so detect_anomalies
    actually fires: one steadily-busy client that then goes silent, one that
    spikes, plus the duplicate-ip client split across two ids."""
    random.seed(99)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)
    now = _ANOMALY_NOW
    hours = 24 * 8  # 8 days of hourly history

    def emit(cid, hour_ago, count):
        base = now - hour_ago * 3600
        did = _idstore_domain_id(c, "steady.example.com")
        for _ in range(count):
            ts = base + random.randint(0, 3599)
            c.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (ts, 1, 2, did, cid),
            )

    silent = _idstore_client_id(c, "192.168.0.20", "goes-silent")
    spike = _idstore_client_id(c, "192.168.0.21", "spikes")
    dup_a = _idstore_client_id(c, _DUP_IP, "")
    dup_b = _idstore_client_id(c, _DUP_IP, "localhost")
    for h in range(hours, 0, -1):
        emit(silent, h, 0 if h <= 3 else 40)      # busy baseline, silent last 3h
        emit(spike, h, 300 if h == 1 else 20)     # steady then a sharp spike now
        emit(dup_a, h, 5)                          # duplicate-ip client, both ids
        emit(dup_b, h, 5)
    conn.commit()
    conn.close()


class _FixedClock:
    def time(self):
        return _ANOMALY_NOW


def test_detect_anomalies_matches(tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    _build_anomaly_db(path)
    monkeypatch.setattr(db, "DB_PATH", path)
    # Pin detect_anomalies' clock to the build-time `now`: it reads time.time()
    # internally, so without this the two sequential calls would use slightly
    # different baseline windows (a wall-clock race, not a path difference).
    monkeypatch.setattr(db, "time", _FixedClock())
    view, idp = _both(monkeypatch, db.detect_anomalies)

    def key(a):
        return (a["ip"], a["kind"])

    assert sorted(view, key=key) == sorted(idp, key=key)
    # The rewrite must actually detect something here, not trivially match on [].
    kinds = {(a["ip"], a["kind"]) for a in idp}
    assert ("192.168.0.20", "silent") in kinds
    assert ("192.168.0.21", "spike") in kinds


# ==========================================================================
# Orphaned-id regression.
#
# An ORPHANED id is a domain/client integer stored on a query_storage row whose
# lookup row is MISSING from domain_by_id / client_by_id entirely (distinct from
# the duplicate-ip case above, where the row exists but shares a value). This is
# a real latent state (Pi-hole internal GC/vacuum can drop old lookup rows; a
# different user's DB can be in a different state).
#
# The trusted `queries` VIEW resolves every orphan to NULL via its CASE
# subquery. Two consequences the id fast path MUST reproduce exactly:
#   * COUNT(DISTINCT ...) skips NULLs -> an orphan is NOT a distinct domain/
#     client. Grouping/counting on the raw id instead treats each orphaned id as
#     its own value, OVERCOUNTING uniques.
#   * GROUP BY folds all NULLs into ONE group -> every orphaned id (however many
#     distinct integers) collapses into a SINGLE None output row whose count is
#     their sum. A raw-id GROUP BY emits one row PER orphaned id instead.
#
# These IDs are inserted straight into query_storage and deliberately never
# registered in domain_by_id / client_by_id, so they orphan.
# --------------------------------------------------------------------------

_ORPHAN_DOMAIN_IDS = [9001, 9002, 9003]  # never inserted into domain_by_id
_ORPHAN_CLIENT_IDS = [9101, 9102]        # never inserted into client_by_id


def _build_orphans(
    path: str,
    *,
    orphan_domain_ids=(),
    orphan_client_ids=(),
    dup_ip: bool = True,
) -> None:
    """Normalized-layout DB seeded with normal traffic plus rows referencing the
    given orphaned domain/client ids. Orphan counts are staggered (different per
    id) so a broken merge that kept them separate would rank/count differently
    from the view's single collapsed group -- a uniform count could hide it."""
    random.seed(4321)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)
    now = 1_700_000_000

    client_ids = [_idstore_client_id(c, ip, name) for ip, name in _CLIENTS]
    if dup_ip:
        client_ids.append(_idstore_client_id(c, _DUP_IP, ""))
        client_ids.append(_idstore_client_id(c, _DUP_IP, "localhost"))
    domain_ids = [_idstore_domain_id(c, d) for d in _DOMAINS]
    span = 10 * 86400

    def emit(n, did_pool, cid_pool):
        for _ in range(n):
            c.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (
                    now - random.randint(0, span),
                    random.choice(_TYPES),
                    random.choice(_STATUSES),
                    random.choice(did_pool),
                    random.choice(cid_pool),
                ),
            )

    # Normal traffic: resolvable domains, resolvable clients.
    emit(3000, domain_ids, client_ids)
    # Orphan-domain traffic: resolvable clients, orphaned domain ids (staggered).
    for k, odid in enumerate(orphan_domain_ids):
        emit(20 + 7 * k, [odid], client_ids)
    # Orphan-client traffic: resolvable domains, orphaned client ids (staggered).
    for k, ocid in enumerate(orphan_client_ids):
        emit(15 + 5 * k, domain_ids, [ocid])
    # Rows orphaned on BOTH axes at once (only if both kinds are present).
    if orphan_domain_ids and orphan_client_ids:
        emit(10, [orphan_domain_ids[0]], [orphan_client_ids[0]])

    conn.commit()
    conn.close()


@pytest.fixture
def orphan_db(tmp_path, monkeypatch):
    """Factory: build an orphan-seeded DB for a given scenario and point db at
    it. Returns the path so tests can compute ground truth against it."""

    def _make(**kwargs) -> str:
        path = str(tmp_path / "pihole-FTL.db")
        _build_orphans(path, **kwargs)
        monkeypatch.setattr(db, "DB_PATH", path)
        return path

    return _make


def _orphan_presence(path: str) -> tuple[int, int]:
    """(#distinct orphaned domain ids, #distinct orphaned client ids) actually
    present in query_storage -- i.e. raw ids with no lookup row. Computed
    directly (not via raw-minus-resolved, which the duplicate-ip collapse would
    also inflate) so it's a clean, independent witness that the fixture is
    non-vacuous: >0 means the view really did resolve orphans to NULL, so the id
    path could only match it by excluding them (the pre-fix raw-id code would
    fail these tests)."""
    conn = truth(path)
    dom = conn.execute(
        "SELECT COUNT(DISTINCT domain) FROM query_storage "
        "WHERE typeof(domain)='integer' AND domain NOT IN (SELECT id FROM domain_by_id)"
    ).fetchone()[0]
    cli = conn.execute(
        "SELECT COUNT(DISTINCT client) FROM query_storage "
        "WHERE typeof(client)='integer' AND client NOT IN (SELECT id FROM client_by_id)"
    ).fetchone()[0]
    conn.close()
    return dom, cli


# Scenarios spanning the task's required cases: a single orphan, MULTIPLE
# orphans (the merge-into-one-row case), each axis alone, and both axes together
# on top of the duplicate-ip client.
_SCENARIOS = {
    "single_orphan_domain": dict(orphan_domain_ids=[9001]),
    "multi_orphan_domains": dict(orphan_domain_ids=_ORPHAN_DOMAIN_IDS),
    "single_orphan_client": dict(orphan_client_ids=[9101]),
    "multi_orphan_clients": dict(orphan_client_ids=_ORPHAN_CLIENT_IDS),
    "both_axes_with_dup_ip": dict(
        orphan_domain_ids=_ORPHAN_DOMAIN_IDS,
        orphan_client_ids=_ORPHAN_CLIENT_IDS,
        dup_ip=True,
    ),
}


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_summary_orphans_match_view(orphan_db, monkeypatch, scenario):
    path = orphan_db(**_SCENARIOS[scenario])
    dom_orphans, cli_orphans = _orphan_presence(path)
    view, idp = _both(monkeypatch, lambda: db.summary(None, None, None))
    # Byte-for-byte match with the trusted view is the core invariant.
    assert view == idp
    # Non-vacuous: the scenario really does contain orphaned ids for the axis
    # it targets, so a raw-id count would have overcounted and this would fail.
    if _SCENARIOS[scenario].get("orphan_domain_ids"):
        assert dom_orphans == len(_SCENARIOS[scenario]["orphan_domain_ids"])
    if _SCENARIOS[scenario].get("orphan_client_ids"):
        assert cli_orphans == len(_SCENARIOS[scenario]["orphan_client_ids"])


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_top_domains_orphans_match_view(orphan_db, monkeypatch, scenario):
    path = orphan_db(**_SCENARIOS[scenario])
    # Full ranking so ties at the boundary can't cause spurious diffs.
    view, idp = _both(monkeypatch, lambda: db.top_domains(None, None, limit=1000))

    # CRITICAL: compare the raw LISTS, not {domain: count} dicts -- a dict would
    # silently collapse multiple None rows into one and HIDE the merge bug. Every
    # orphaned domain id (there are several in the multi scenario) must appear as
    # exactly ONE None row, matching the view's single NULL group.
    assert [r["domain"] for r in idp].count(None) == [r["domain"] for r in view].count(None)
    if _SCENARIOS[scenario].get("orphan_domain_ids"):
        assert [r["domain"] for r in idp].count(None) == 1
        vnone = next(r["count"] for r in view if r["domain"] is None)
        inone = next(r["count"] for r in idp if r["domain"] is None)
        assert inone == vnone  # summed across all orphaned ids, not one id's share
    # Non-orphan domains resolve and match exactly.
    assert {r["domain"]: r["count"] for r in view if r["domain"] is not None} == {
        r["domain"]: r["count"] for r in idp if r["domain"] is not None
    }


def _build_ranked_orphans(path: str) -> None:
    """A DB tuned so the merged orphan group must WIN a tight top-N: three
    orphaned domain ids whose counts are each individually BELOW every real
    domain's count, but whose SUM is the single largest group. A correct merge
    ranks the collapsed None group #1; the pre-fix code emits three small
    separate None rows that never reach the top -- so the ranking diverges."""
    random.seed(2024)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)
    now = 1_700_000_000
    cid = _idstore_client_id(c, "192.168.0.40", "host")
    span = 10 * 86400

    def emit(did, n):
        for _ in range(n):
            c.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (now - random.randint(0, span), 1, 2, did, cid),
            )

    # Real domains: exactly 100 rows each (well-separated, no ties).
    for d in _DOMAINS[:6]:
        emit(_idstore_domain_id(c, d), 100)
    # Orphan ids: 60 + 65 + 70 = 195 -> merged group is #1, each part < 100.
    emit(9001, 60)
    emit(9002, 65)
    emit(9003, 70)
    conn.commit()
    conn.close()


def test_top_domains_orphans_rank_into_limit(tmp_path, monkeypatch):
    """A tight LIMIT where the merged orphan group must out-rank real domains:
    the collapsed None count has to participate in ranking as one group, so it
    can't be truncated away before merging. View is the oracle."""
    path = str(tmp_path / "pihole-FTL.db")
    _build_ranked_orphans(path)
    monkeypatch.setattr(db, "DB_PATH", path)
    for lim in (1, 3, 8):
        view, idp = _both(monkeypatch, lambda lim=lim: db.top_domains(None, None, limit=lim))
        # Tie-robust: identical count sequence proves identical ranking/merge.
        assert [r["count"] for r in view] == [r["count"] for r in idp]
        assert [r["domain"] for r in idp].count(None) <= 1
    # And the merged group really is #1 (proves the scenario bites): with the
    # pre-fix code the top row would be a 100-count real domain, not None/195.
    _force(monkeypatch, True)
    top1 = db.top_domains(None, None, limit=1)
    assert top1 == [{"domain": None, "count": 195}]


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_top_clients_orphans_match_view(orphan_db, monkeypatch, scenario):
    path = orphan_db(**_SCENARIOS[scenario])
    view, idp = _both(monkeypatch, lambda: db.top_clients(None, limit=1000))
    # Compare lists (not ip-keyed dicts) so multiple orphan client ids collapsing
    # to more than one None row would be caught.
    assert [r["ip"] for r in idp].count(None) == [r["ip"] for r in view].count(None)
    vm = {r["ip"]: (r["count"], r["name"]) for r in view}
    im = {r["ip"]: (r["count"], r["name"]) for r in idp}
    assert vm == im
    if _SCENARIOS[scenario].get("orphan_client_ids"):
        assert None in im  # orphaned clients present as a single merged None row


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_new_clients_orphans_match_view(orphan_db, monkeypatch, scenario):
    orphan_db(**_SCENARIOS[scenario])
    cutoff = 1_700_000_000 - 20 * 86400
    view, idp = _both(monkeypatch, lambda: db.new_clients(cutoff))
    assert [c["ip"] for c in idp].count(None) == [c["ip"] for c in view].count(None)
    vm = {c["ip"]: (c["first_seen"], c["total"], c["name"]) for c in view}
    im = {c["ip"]: (c["first_seen"], c["total"], c["name"]) for c in idp}
    assert vm == im


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_client_activity_orphans_match_view(orphan_db, monkeypatch, scenario):
    orphan_db(**_SCENARIOS[scenario])

    def call():
        return db.client_activity(None, 1_700_000_100, limit=100, buckets=20)

    view, idp = _both(monkeypatch, call)
    assert [c["ip"] for c in idp].count(None) == [c["ip"] for c in view].count(None)
    vm = {c["ip"]: c for c in view}
    im = {c["ip"]: c for c in idp}
    assert vm.keys() == im.keys()
    for ip in vm:
        assert vm[ip] == im[ip]


@pytest.mark.parametrize("scenario", list(_SCENARIOS))
def test_query_types_and_timeseries_orphans_match_view(orphan_db, monkeypatch, scenario):
    orphan_db(**_SCENARIOS[scenario])
    v, i = _both(monkeypatch, lambda: db.query_types(None, None, None))
    assert v == i
    v2, i2 = _both(
        monkeypatch, lambda: db.timeseries(None, None, 1_700_000_100, buckets=50)
    )
    assert v2 == i2


def _build_anomaly_orphans(path: str) -> None:
    """detect_anomalies-shaped DB (long hourly history) whose busy, silent, and
    spiking clients include an ORPHANED client id, so _anomaly_inputs' merge-by-
    resolved-ip must fold that id into the same None bucket the view produces."""
    random.seed(7)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)
    now = _ANOMALY_NOW
    hours = 24 * 8

    def emit(cid, hour_ago, count):
        base = now - hour_ago * 3600
        did = _idstore_domain_id(c, "steady.example.com")
        for _ in range(count):
            ts = base + random.randint(0, 3599)
            c.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (ts, 1, 2, did, cid),
            )

    real = _idstore_client_id(c, "192.168.0.30", "real-busy")
    orphan_a = 9201  # never registered in client_by_id -> resolves to None
    orphan_b = 9202
    for h in range(hours, 0, -1):
        emit(real, h, 30)
        emit(orphan_a, h, 12)  # two orphan ids -> must merge into one None client
        emit(orphan_b, h, 8)
    conn.commit()
    conn.close()


def test_anomaly_inputs_orphans_match_view(tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    _build_anomaly_orphans(path)
    monkeypatch.setattr(db, "DB_PATH", path)
    dom_orphans, cli_orphans = _orphan_presence(path)
    assert cli_orphans == 2  # both orphan client ids are present and unresolved

    baseline_start = _ANOMALY_NOW - db.BASELINE_DAYS * 86400
    view, idp = _both(
        monkeypatch, lambda: db._anomaly_inputs(_ANOMALY_NOW, baseline_start)
    )
    # _anomaly_inputs returns (per_client_buckets, first_seen, names). The two
    # orphaned ids must appear as a SINGLE None-keyed client with summed buckets,
    # min first-seen, and a None name -- exactly the view's collapsed NULL group.
    assert view == idp
    per_client_buckets, first_seen, names = idp
    assert None in per_client_buckets
    assert None in first_seen
    assert names.get(None) is None
