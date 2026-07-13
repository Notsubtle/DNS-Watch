"""rollups.read_domain_status_changes / rollups.read_period_comparison --
the blocklist-effectiveness "newly blocked/unblocked" view and the
period-over-period "what changed" diff view. Both are built on the new
domain_status_daily rollup table, exercised here via refresh_rollups() on
the idstore schema (the accumulation code is schema-agnostic -- every schema
funnels through the same _Deltas.add(), already proven cross-schema by
test_rollups.py's summary-agreement tests -- so this focuses on the new
read-side logic rather than re-proving accumulation correctness per schema).
"""

from __future__ import annotations

import sqlite3

import pytest

from conftest import _idstore_client_id, _idstore_domain_id, _idstore_schema

DAY = 86400
ALLOWED = 2  # db.ALLOWED_STATUSES member
BLOCKED = 1  # db.BLOCKED_STATUSES member
NOW = 1_800_000_000  # fixed epoch so day-bucketing math is deterministic


@pytest.fixture
def rstore(tmp_path, monkeypatch):
    from app import rollups
    path = str(tmp_path / "dnswatch.db")
    monkeypatch.setattr(rollups, "STORE_PATH", path)
    return path


@pytest.fixture
def idb(tmp_path, monkeypatch):
    from app import db
    path = str(tmp_path / "pihole-FTL.db")
    monkeypatch.setattr(db, "DB_PATH", path)
    db.detect_schema.cache_clear()
    yield path
    db.detect_schema.cache_clear()


def _insert(path: str, ip: str, name: str, domain: str, status: int, ts: int) -> None:
    conn = sqlite3.connect(path)
    c = conn.cursor()
    cid = _idstore_client_id(c, ip, name)
    did = _idstore_domain_id(c, domain)
    c.execute(
        "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
        (ts, 1, status, did, cid),
    )
    conn.commit()
    conn.close()


def _fresh_idstore_db(path: str) -> None:
    conn = sqlite3.connect(path)
    _idstore_schema(conn.cursor())
    conn.commit()
    conn.close()


def test_domain_status_changes_detects_newly_blocked_and_unblocked(idb, rstore):
    from app import rollups
    _fresh_idstore_db(idb)

    # "adserver.example.com": allowed throughout the 14-day prior window,
    # then blocked (5x) in the last 3 days -- a real status change.
    for day_back in range(4, 18):
        _insert(idb, "192.168.1.10", "laptop", "adserver.example.com", ALLOWED, NOW - day_back * DAY)
    for day_back in range(0, 3):
        _insert(idb, "192.168.1.10", "laptop", "adserver.example.com", BLOCKED, NOW - day_back * DAY)

    # "unblocked-cdn.example.com": blocked throughout the prior window, then
    # allowed (still queried, just no longer blocked) recently.
    for day_back in range(4, 18):
        _insert(idb, "192.168.1.10", "laptop", "unblocked-cdn.example.com", BLOCKED, NOW - day_back * DAY)
    for day_back in range(0, 3):
        _insert(idb, "192.168.1.10", "laptop", "unblocked-cdn.example.com", ALLOWED, NOW - day_back * DAY)

    # "steady.example.com": blocked the whole time -- no change, must not appear.
    for day_back in range(0, 18):
        _insert(idb, "192.168.1.10", "laptop", "steady.example.com", BLOCKED, NOW - day_back * DAY)

    rollups.refresh_rollups()
    import time
    from unittest import mock
    with mock.patch("time.time", return_value=NOW):
        result = rollups.read_domain_status_changes()

    assert result is not None
    blocked_domains = {r["domain"] for r in result["newly_blocked"]}
    unblocked_domains = {r["domain"] for r in result["newly_unblocked"]}
    assert "adserver.example.com" in blocked_domains
    assert "unblocked-cdn.example.com" in unblocked_domains
    assert "steady.example.com" not in blocked_domains
    assert "steady.example.com" not in unblocked_domains


def test_domain_status_changes_ignores_brand_new_domains(idb, rstore):
    """A domain that's ONLY ever been queried in the recent window (no prior
    presence at all) is a new-domain signal, not a status-change signal --
    must not show up in newly_blocked even though prior_blocked == 0."""
    from app import rollups
    _fresh_idstore_db(idb)
    for day_back in range(0, 3):
        _insert(idb, "192.168.1.10", "laptop", "brand-new-blocked.example.com", BLOCKED, NOW - day_back * DAY)

    rollups.refresh_rollups()
    from unittest import mock
    with mock.patch("time.time", return_value=NOW):
        result = rollups.read_domain_status_changes()

    assert not any(r["domain"] == "brand-new-blocked.example.com" for r in result["newly_blocked"])


def test_domain_status_changes_none_when_rollup_not_ready(rstore):
    from app import rollups
    assert rollups.read_domain_status_changes() is None


def test_period_comparison_block_rate_and_new_device(idb, rstore):
    from app import rollups
    _fresh_idstore_db(idb)

    # Prior period (days 8-14 back): mostly allowed.
    for day_back in range(8, 14):
        for _ in range(8):
            _insert(idb, "192.168.1.10", "laptop", "steady.example.com", ALLOWED, NOW - day_back * DAY)
        _insert(idb, "192.168.1.10", "laptop", "steady.example.com", BLOCKED, NOW - day_back * DAY)
    # Current period (days 0-6 back): much higher block share.
    for day_back in range(0, 6):
        for _ in range(8):
            _insert(idb, "192.168.1.10", "laptop", "steady.example.com", BLOCKED, NOW - day_back * DAY)
        _insert(idb, "192.168.1.10", "laptop", "steady.example.com", ALLOWED, NOW - day_back * DAY)

    # A brand-new device, first seen inside the current period only.
    _insert(idb, "192.168.1.99", "new_gadget", "steady.example.com", ALLOWED, NOW - 1 * DAY)

    rollups.refresh_rollups()
    from unittest import mock
    with mock.patch("time.time", return_value=NOW):
        result = rollups.read_period_comparison(period_days=7)

    assert result is not None
    assert result["prior_period_available"] is True
    assert result["block_rate_current"] > result["block_rate_prior"]
    assert any(d["ip"] == "192.168.1.99" for d in result["new_devices"])
    assert not any(d["ip"] == "192.168.1.10" for d in result["new_devices"])


def test_period_comparison_flags_unavailable_prior_period(idb, rstore):
    """History only goes back 3 days -- nowhere near a full prior 7-day
    period -- so prior_period_available must be False, not silently 0."""
    from app import rollups
    _fresh_idstore_db(idb)
    for day_back in range(0, 3):
        _insert(idb, "192.168.1.10", "laptop", "steady.example.com", ALLOWED, NOW - day_back * DAY)

    rollups.refresh_rollups()
    from unittest import mock
    with mock.patch("time.time", return_value=NOW):
        result = rollups.read_period_comparison(period_days=7)

    assert result is not None
    assert result["prior_period_available"] is False


def test_period_comparison_none_when_rollup_not_ready(rstore):
    from app import rollups
    assert rollups.read_period_comparison() is None
