"""Storage stats and alert event pruning (#59)."""

from __future__ import annotations

import sqlite3
import time


def _insert_event(conn: sqlite3.Connection, created_at: int, message: str) -> None:
    conn.execute(
        "INSERT INTO alert_events "
        "(rule_id, rule_name, type, severity, message, dedup_key, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (None, "Test rule", "new_device", "info", message, f"test:{message}", created_at),
    )


def test_storage_stats_counts_alert_events(client, store):
    from app import alerts

    alerts.init_store()
    now = int(time.time())
    with sqlite3.connect(store) as conn:
        _insert_event(conn, now - 10, "one")
        _insert_event(conn, now - 5, "two")
        conn.commit()

    r = client.get("/api/storage-stats")
    assert r.status_code == 200
    body = r.json()
    assert body["db_size_bytes"] >= 0
    assert body["alert_events_count"] == 2


def test_prune_events_deletes_only_events_older_than_cutoff(client, store):
    from app import alerts

    alerts.init_store()
    now = int(time.time())
    with sqlite3.connect(store) as conn:
        _insert_event(conn, now - 100 * 86400, "old")
        _insert_event(conn, now - 10 * 86400, "newer")
        conn.commit()

    r = client.post("/api/storage/prune-events", json={"older_than_days": 90})
    assert r.status_code == 200
    assert r.json() == {"deleted": 1}

    with sqlite3.connect(store) as conn:
        rows = conn.execute("SELECT message FROM alert_events ORDER BY message").fetchall()
    assert [r[0] for r in rows] == ["newer"]


def test_prune_events_rejects_invalid_days(client):
    r = client.post("/api/storage/prune-events", json={"older_than_days": 0})
    assert r.status_code == 400
