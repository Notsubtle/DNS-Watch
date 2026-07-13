"""NXDOMAIN-rate anomaly detection (db._nxdomain_anomalies) — only meaningful
on the normalized "idstore" layout, since `reply_type` doesn't exist on the
older schemas at all (same honest-scope precedent as slowest_domains()).
"""

from __future__ import annotations

import random
import sqlite3
import time

from conftest import _idstore_client_id, _idstore_domain_id

NXDOMAIN = 2  # app.db.NXDOMAIN_REPLY_TYPE


def _insert_idstore_queries(path: str, ip: str, name: str, ts_and_reply: list[tuple[float, int | None]]) -> None:
    """Insert one row per (timestamp, reply_type) pair for a single client,
    on the idstore schema directly — the shared conftest helper has no
    reply_type knob, and this feature only exists on this one schema."""
    conn = sqlite3.connect(path)
    c = conn.cursor()
    cid = _idstore_client_id(c, ip, name)
    did = _idstore_domain_id(c, "lookup.example.com")
    for ts, reply_type in ts_and_reply:
        c.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client,reply_type) "
            "VALUES (?,?,?,?,?,?)",
            (ts, 1, 2, did, cid, reply_type),
        )
    conn.commit()
    conn.close()


def _client_rows(now: int, baseline_count: int, baseline_nx: int, recent_count: int, recent_nx: int):
    """baseline: spread over days 1-7 back; recent: spread over the last 3h.

    Uses its own Random instance rather than the shared `random` module --
    the module-level PRNG is shared across the whole test session, and
    drawing from it here would shift the sequence every other test that
    relies on unseeded `random` calls sees, which is exactly what exposed a
    latent flaky test elsewhere in the suite during review."""
    rng = random.Random(f"{now}-{baseline_count}-{baseline_nx}-{recent_count}-{recent_nx}")
    rows = []
    for i in range(baseline_count):
        ts = now - rng.randint(4 * 3600, 6 * 86400)
        reply = NXDOMAIN if i < baseline_nx else 4  # 4 = REPLY_IP, an ordinary success
        rows.append((ts, reply))
    for i in range(recent_count):
        # Kept off both edges of the 3h recent window (60s buffer) so a
        # few seconds' drift between this test's `now` and detect_anomalies()'s
        # own can't flip a boundary row across is_recent.
        ts = now - rng.randint(60, 3 * 3600 - 60)
        reply = NXDOMAIN if i < recent_nx else 4
        rows.append((ts, reply))
    return rows


def test_nxdomain_spike_flagged_on_idstore(ftl):
    from app import db
    if ftl["schema"] != "idstore":
        return  # feature is a no-op elsewhere; covered by test_no_op_on_older_schemas below
    now = int(time.time())
    # Healthy baseline (~2% NXDOMAIN, well-sampled) then a burst of failed
    # lookups in the recent window (~60%) -- clears both the 3x-baseline and
    # the absolute floor.
    rows = _client_rows(now, baseline_count=100, baseline_nx=2, recent_count=20, recent_nx=12)
    _insert_idstore_queries(ftl["path"], "10.0.0.60", "dga_bot", rows)

    # This client's recent burst can also legitimately trip the unrelated
    # volume-spike check on the same ip -- match on kind, not just ip, so
    # this test only asserts on the nxdomain anomaly specifically.
    hit = next((a for a in db.detect_anomalies() if a["ip"] == "10.0.0.60" and a["kind"] == "nxdomain"), None)
    assert hit is not None
    assert hit["current_value"] > 50
    assert hit["baseline_avg"] < 10


def test_nxdomain_not_flagged_when_baseline_already_high(ftl):
    """A client whose baseline NXDOMAIN rate is already elevated (e.g. a
    device that just legitimately fails a lot of lookups) must not fire
    just because the recent window matches its own normal rate."""
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    rows = _client_rows(now, baseline_count=100, baseline_nx=40, recent_count=20, recent_nx=8)
    _insert_idstore_queries(ftl["path"], "10.0.0.61", "chatty_app", rows)

    assert not any(a["ip"] == "10.0.0.61" and a["kind"] == "nxdomain" for a in db.detect_anomalies())


def test_nxdomain_not_flagged_below_absolute_floor(ftl):
    """Recent rate technically clears 3x a near-zero baseline but stays
    under the absolute floor -- must not fire on a trivial blip."""
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    # baseline ~1%, recent ~5% (>3x, but under the 15% floor).
    rows = _client_rows(now, baseline_count=100, baseline_nx=1, recent_count=20, recent_nx=1)
    _insert_idstore_queries(ftl["path"], "10.0.0.62", "mostly_fine", rows)

    assert not any(a["ip"] == "10.0.0.62" and a["kind"] == "nxdomain" for a in db.detect_anomalies())


def test_nxdomain_not_flagged_with_insufficient_sample(ftl):
    """Too few queries in either window to trust a rate at all."""
    from app import db
    if ftl["schema"] != "idstore":
        return
    now = int(time.time())
    rows = _client_rows(now, baseline_count=5, baseline_nx=1, recent_count=3, recent_nx=3)
    _insert_idstore_queries(ftl["path"], "10.0.0.63", "too_few", rows)

    assert not any(a["ip"] == "10.0.0.63" and a["kind"] == "nxdomain" for a in db.detect_anomalies())


def test_no_op_on_older_schemas(ftl):
    """No `reply_type` column exists on new/old/real -- must return []
    quietly (never error), matching slowest_domains()'s precedent."""
    from app import db
    if ftl["schema"] == "idstore":
        return
    now = int(time.time())
    assert db._nxdomain_anomalies(now, now - 7 * 86400) == []


def test_detect_anomalies_shares_one_query_storage_scan(ftl, monkeypatch):
    """detect_anomalies() must run _windowed_client_stats exactly once and
    hand the same result to both _nxdomain_anomalies and _latency_anomalies
    -- see its own comment for why a second independent query_storage scan
    per poll (ANOMALIES_REFRESH_MS in App.tsx) is the thing being guarded
    against here."""
    from app import db

    calls = []
    orig = db._windowed_client_stats

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return orig(*args, **kwargs)

    monkeypatch.setattr(db, "_windowed_client_stats", spy)
    db.detect_anomalies()
    assert len(calls) == 1, "expected exactly one shared query_storage scan per detect_anomalies() call"
