"""Unified per-device investigation timeline (#5) --
GET /api/device-names/{ip}/timeline merges name_history.history_for() and
alerts.events_for_client() into one chronological feed."""

from __future__ import annotations

import time

from app import alerts, name_history


def test_events_for_client_scoped_and_ordered(tmp_path, monkeypatch):
    monkeypatch.setattr(alerts, "STORE_PATH", str(tmp_path / "dnswatch.db"))
    alerts.init_store()
    now = int(time.time())
    with alerts._connect() as conn:
        conn.execute(
            "INSERT INTO alert_events (rule_id, rule_name, type, severity, message, dedup_key, "
            "created_at, client_ip) VALUES (?,?,?,?,?,?,?,?)",
            (1, "R1", "new_device", "info", "hello", "d1", now - 10, "10.0.0.5"),
        )
        conn.execute(
            "INSERT INTO alert_events (rule_id, rule_name, type, severity, message, dedup_key, "
            "created_at, client_ip) VALUES (?,?,?,?,?,?,?,?)",
            (1, "R1", "new_device", "info", "other client", "d2", now - 5, "10.0.0.6"),
        )
        conn.execute(
            "INSERT INTO alert_events (rule_id, rule_name, type, severity, message, dedup_key, "
            "created_at, client_ip) VALUES (?,?,?,?,?,?,?,?)",
            (1, "R1", "new_device", "info", "hello again", "d3", now, "10.0.0.5"),
        )
        conn.commit()

    events = alerts.events_for_client("10.0.0.5")
    assert [e["message"] for e in events] == ["hello again", "hello"]
    assert all(e["client_ip"] == "10.0.0.5" for e in events)


def test_api_device_timeline_merges_and_sorts(client, ftl, tmp_path, monkeypatch):
    monkeypatch.setattr(name_history, "STORE_PATH", str(tmp_path / "dnswatch.db"))
    monkeypatch.setattr(alerts, "STORE_PATH", str(tmp_path / "dnswatch.db"))
    ip = "192.168.1.13"

    name_history.record_change(ip, "manual", None, "Old Name")
    time.sleep(0.01)
    with alerts._connect() as conn:
        alerts.init_store()
        conn.execute(
            "INSERT INTO alert_events (rule_id, rule_name, type, severity, message, dedup_key, "
            "created_at, client_ip) VALUES (?,?,?,?,?,?,?,?)",
            (1, "R1", "new_device", "info", "seen", "dX", int(time.time()), ip),
        )
        conn.commit()
    time.sleep(0.01)
    name_history.record_change(ip, "manual", "Old Name", "New Name")

    resp = client.get(f"/api/device-names/{ip}/timeline")
    assert resp.status_code == 200
    body = resp.json()
    types = [e["type"] for e in body]
    assert "name_change" in types
    assert "alert_event" in types
    # Most-recent-first: the last rename must come before the earlier ones.
    ats = [e["at"] for e in body]
    assert ats == sorted(ats, reverse=True)


def test_api_device_timeline_empty_for_unknown_device(client, ftl):
    resp = client.get("/api/device-names/10.0.0.250/timeline")
    assert resp.status_code == 200
    assert resp.json() == []
