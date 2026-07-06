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
