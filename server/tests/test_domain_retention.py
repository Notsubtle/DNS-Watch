"""Retention for the two unbounded-growth rollup tables (#10) --
rollups.storage_stats/prune_domain_history, and the storage endpoints that
expose them. seen_domains and domain_status_daily are both explicitly
disclosed in rollups.py as having "no retention policy in v1"."""

from __future__ import annotations

import time

from app import rollups


def test_storage_stats_counts_both_tables(client, ftl):
    now = int(time.time())
    with rollups._connect() as conn:
        rollups.init_rollup_store()
        conn.execute("INSERT INTO seen_domains (domain, first_seen) VALUES (?, ?)", ("a.example", now))
        conn.execute(
            "INSERT INTO domain_status_daily (domain, day, allowed_count, blocked_count) "
            "VALUES (?, ?, ?, ?)",
            ("a.example", "2020-01-01", 1, 0),
        )
        conn.commit()

    stats = rollups.storage_stats()
    assert stats["seen_domains_count"] >= 1
    assert stats["domain_status_daily_count"] >= 1


def test_prune_domain_history_deletes_only_old_rows(client, ftl):
    now = int(time.time())
    old_ts = now - 200 * 86400
    with rollups._connect() as conn:
        rollups.init_rollup_store()
        conn.execute("INSERT INTO seen_domains (domain, first_seen) VALUES (?, ?)", ("old.example", old_ts))
        conn.execute("INSERT INTO seen_domains (domain, first_seen) VALUES (?, ?)", ("new.example", now))
        conn.execute(
            "INSERT INTO domain_status_daily (domain, day, allowed_count, blocked_count) VALUES (?,?,?,?)",
            ("old.example", "2000-01-01", 1, 0),
        )
        conn.execute(
            "INSERT INTO domain_status_daily (domain, day, allowed_count, blocked_count) VALUES (?,?,?,?)",
            ("new.example", rollups._day_str(now), 1, 0),
        )
        conn.commit()

    result = rollups.prune_domain_history(180)
    assert result["seen_domains_deleted"] == 1
    assert result["domain_status_daily_deleted"] == 1

    with rollups._connect() as conn:
        remaining = {r["domain"] for r in conn.execute("SELECT domain FROM seen_domains")}
        remaining_status = {r["domain"] for r in conn.execute("SELECT domain FROM domain_status_daily")}
    assert remaining == {"new.example"}
    assert remaining_status == {"new.example"}


def test_prune_domain_history_rejects_invalid_days(ftl):
    for bad in (0, -1, "abc"):
        try:
            rollups.prune_domain_history(bad)  # type: ignore[arg-type]
            assert False, f"expected ValueError for {bad!r}"
        except ValueError:
            pass


def test_api_storage_stats_includes_domain_counts(client, ftl):
    resp = client.get("/api/storage-stats")
    assert resp.status_code == 200
    body = resp.json()
    assert "seen_domains_count" in body
    assert "domain_status_daily_count" in body
    assert "alert_events_count" in body  # still present -- this endpoint merges both modules


def test_api_prune_domain_history_endpoint(client, ftl):
    now = int(time.time())
    with rollups._connect() as conn:
        rollups.init_rollup_store()
        conn.execute(
            "INSERT INTO seen_domains (domain, first_seen) VALUES (?, ?)",
            ("ancient.example", now - 400 * 86400),
        )
        conn.commit()

    resp = client.post("/api/storage/prune-domain-history", json={"older_than_days": 180})
    assert resp.status_code == 200
    body = resp.json()
    assert body["seen_domains_deleted"] >= 1


def test_api_prune_domain_history_rejects_invalid_days(client, ftl):
    resp = client.post("/api/storage/prune-domain-history", json={"older_than_days": 0})
    assert resp.status_code == 400
