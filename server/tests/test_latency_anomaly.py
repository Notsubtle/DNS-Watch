"""Resolver latency degradation (#4/#4b): db._latency_anomalies (per-client,
wired into detect_anomalies as kind "latency") and db.network_latency_health
(network-wide, deliberately NOT part of detect_anomalies -- see its module
note). Only meaningful on the normalized "idstore" layout, since `reply_time`
doesn't exist on the older schemas at all (same honest-scope precedent as
slowest_domains()/NXDOMAIN).
"""

from __future__ import annotations

import random
import sqlite3
import time

from conftest import _idstore_client_id, _idstore_domain_id


def _insert_idstore_queries(path: str, ip: str, name: str, ts_and_reply_ms: list[tuple[float, float]]) -> None:
    conn = sqlite3.connect(path)
    c = conn.cursor()
    cid = _idstore_client_id(c, ip, name)
    did = _idstore_domain_id(c, "lookup.example.com")
    for ts, reply_ms in ts_and_reply_ms:
        c.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client,reply_time) "
            "VALUES (?,?,?,?,?,?)",
            (ts, 1, 2, did, cid, reply_ms / 1000),  # reply_time is stored in seconds
        )
    conn.commit()
    conn.close()


def _rows(now: int, baseline_count: int, baseline_ms: float, recent_count: int, recent_ms: float, seed: str):
    rng = random.Random(seed)
    rows = []
    for _ in range(baseline_count):
        ts = now - rng.randint(4 * 3600, 6 * 86400)
        rows.append((ts, baseline_ms))
    for _ in range(recent_count):
        ts = now - rng.randint(60, 3 * 3600 - 60)
        rows.append((ts, recent_ms))
    return rows


def test_client_latency_degradation_flagged_on_idstore(ftl):
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    rows = _rows(now, baseline_count=100, baseline_ms=20, recent_count=20, recent_ms=200, seed="lat1")
    _insert_idstore_queries(ftl["path"], "10.0.0.70", "slow_now", rows)

    hit = next((a for a in db.detect_anomalies() if a["ip"] == "10.0.0.70" and a["kind"] == "latency"), None)
    assert hit is not None
    assert hit["current_value"] > hit["baseline_avg"]
    assert abs(hit["baseline_avg"] - 20) < 5


def test_client_latency_not_flagged_below_floor(ftl):
    """Recent avg technically clears 2x a near-zero baseline but stays under
    the absolute floor -- must not fire on a trivial blip."""
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    rows = _rows(now, baseline_count=100, baseline_ms=5, recent_count=20, recent_ms=15, seed="lat2")
    _insert_idstore_queries(ftl["path"], "10.0.0.71", "mostly_fine", rows)

    assert not any(a["ip"] == "10.0.0.71" and a["kind"] == "latency" for a in db.detect_anomalies())


def test_client_latency_not_flagged_with_insufficient_sample(ftl):
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    rows = _rows(now, baseline_count=5, baseline_ms=20, recent_count=3, recent_ms=200, seed="lat3")
    _insert_idstore_queries(ftl["path"], "10.0.0.72", "too_few", rows)

    assert not any(a["ip"] == "10.0.0.72" and a["kind"] == "latency" for a in db.detect_anomalies())


def test_latency_anomalies_no_op_on_older_schemas(ftl):
    from app import db
    if ftl["schema"] == "idstore":
        return
    now = int(time.time())
    assert db._latency_anomalies(now, now - 7 * 86400) == []


def test_network_latency_health_degraded(ftl):
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    rows = _rows(now, baseline_count=100, baseline_ms=20, recent_count=20, recent_ms=200, seed="lat4")
    _insert_idstore_queries(ftl["path"], "10.0.0.73", "net_wide", rows)

    health = db.network_latency_health()
    assert health is not None
    assert health["degraded"] is True
    assert health["recent_avg_ms"] > health["baseline_avg_ms"]


def test_network_latency_health_none_with_insufficient_sample(ftl):
    from app import db
    if ftl["schema"] != "idstore":
        return
    assert db.network_latency_health() is None  # build_ftl seeds no reply_time by default


def test_network_latency_health_none_on_older_schemas(ftl):
    from app import db
    if ftl["schema"] == "idstore":
        return
    assert db.network_latency_health() is None
