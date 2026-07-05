"""Blocklist impact simulator (`db.simulate_pattern` / `POST
/api/simulate-blocklist`) — retrospective "how much traffic would this
Pi-hole-style regex have blocked" over the last N days."""

from __future__ import annotations

import re
import time

import pytest

from conftest import add_client_with_hourly_pattern, truth


def test_matches_and_breakdown_against_ground_truth(ftl):
    from app import db

    pattern = r"tracker\.bad\.co"
    compiled = re.compile(pattern)
    result = db.simulate_pattern(pattern, since=0)

    conn = truth(ftl["path"])
    all_domains = [r["domain"] for r in conn.execute("SELECT domain FROM queries").fetchall()]
    expected_total = sum(1 for d in all_domains if compiled.search(d))

    assert expected_total > 0
    assert result["total_matches"] == expected_total
    assert result["unique_domains"] == 1
    assert result["top_domains"][0]["domain"] == "tracker.bad.co"
    assert result["top_domains"][0]["count"] == expected_total


def test_invalid_regex_raises_re_error(ftl):
    from app import db

    with pytest.raises(re.error):
        db.simulate_pattern("(unclosed", since=0)


def test_breakdown_counts_are_exact_not_sampled(ftl):
    """Regression for the per-client-percentage bug: the domain and client
    breakdowns must be EXACT aggregates, not a capped row sample. Every seeded
    domain contains a literal ".", so this matches every row — and the fixture
    has only a handful of distinct domains, so all of them fit within the
    top-50 cap, meaning the top_domains counts must sum to the true total."""
    from app import db

    result = db.simulate_pattern(".", since=0)

    # Sum of the (uncapped-count) per-domain breakdown == exact total.
    assert sum(d["count"] for d in result["top_domains"]) == result["total_matches"]
    # Sum of per-client matched counts == exact total, too (not a 10k sample).
    assert sum(c["matched_count"] for c in result["clients"]) == result["total_matches"]


def test_client_impact_percentage_matches_expected(ftl):
    from app import db

    # A dedicated client whose ENTIRE window traffic is 20 queries to one
    # domain — a known, hand-computable total for the impact percentage.
    add_client_with_hourly_pattern(
        ftl["path"], ftl["schema"], "10.0.0.99", "sim-test-device", counts_per_hour=[20]
    )

    result = db.simulate_pattern(r"^steady\.example\.com$", since=0)

    entry = next(c for c in result["clients"] if c["ip"] == "10.0.0.99")
    assert entry["matched_count"] == 20
    assert entry["total_count"] == 20
    assert entry["pct_of_client_traffic"] == 100.0


def test_api_invalid_regex_returns_400(client):
    resp = client.post("/api/simulate-blocklist", json={"pattern": "(unclosed", "range": "7d"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid regular expression syntax"


def test_api_empty_pattern_rejected(client):
    resp = client.post("/api/simulate-blocklist", json={"pattern": "   ", "range": "7d"})
    assert resp.status_code == 400


def test_api_clamps_window_to_seven_days_even_if_range_wider(client):
    resp = client.post("/api/simulate-blocklist", json={"pattern": ".", "range": "30d"})
    assert resp.status_code == 200
    body = resp.json()
    now = time.time()
    assert now - 7 * 86400 - 5 <= body["since"] <= now - 7 * 86400 + 5


def test_pathological_pattern_does_not_hang(ftl):
    """Regression for the ReDoS finding: a classic catastrophic-backtracking
    pattern matched against an adversarial domain must not hang the worker —
    the per-row match timeout in db.simulate_pattern() must kick in and treat
    that one row as a non-match rather than blocking the whole scan. Domain
    names logged by Pi-hole are attacker-influenceable (DHCP hostnames land
    here too), so this pairing is a realistic worst case, not a contrived one.
    """
    import sqlite3

    from app import db

    conn = sqlite3.connect(ftl["path"])
    domain = "a" * 40 + "!"  # never matches (a+)+$ -> worst-case backtracking
    if ftl["schema"] == "new":
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (time.time(), 1, 2, domain, 1),
        )
    else:
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (time.time(), 1, 2, domain, "192.168.1.10"),
        )
    conn.commit()
    conn.close()

    start = time.time()
    result = db.simulate_pattern(r"(a+)+$", since=0)
    elapsed = time.time() - start

    assert elapsed < 5  # bounded by the per-row timeout, not the pattern's worst case
    assert isinstance(result["total_matches"], int)


def test_api_valid_pattern_returns_full_shape(client):
    resp = client.post("/api/simulate-blocklist", json={"pattern": "tracker", "range": "7d"})
    assert resp.status_code == 200
    body = resp.json()
    for key in ("pattern", "since", "total_matches", "unique_domains", "top_domains", "clients"):
        assert key in body
