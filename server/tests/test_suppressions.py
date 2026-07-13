"""Permanent alert suppression (#6) -- distinct from the time-boxed snooze
(alert_snoozes): "this rule is a known false positive for this device/domain,
forever", keyed on (rule_id, client_ip, domain) rather than one exact
dedup_key."""

from __future__ import annotations

import pytest


def test_add_suppression_requires_ip_or_domain(client, ftl):
    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 1, "window_minutes": 5}})
    rule_id = r.json()["id"]

    resp = client.post("/api/alert-suppressions", json={"rule_id": rule_id})
    assert resp.status_code == 400


def test_add_suppression_rejects_unknown_rule(client, ftl):
    resp = client.post("/api/alert-suppressions", json={"rule_id": 99999, "client_ip": "10.0.0.5"})
    assert resp.status_code == 400


def test_suppression_blocks_matching_client_across_domains(client, ftl):
    from app import alerts, db

    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 1, "window_minutes": 600}})
    rule_id = r.json()["id"]
    target_ip = next(c["ip"] for c in db.top_clients(None, limit=1))

    client.post("/api/alert-suppressions", json={"rule_id": rule_id, "client_ip": target_ip})

    events = client.get("/api/alerts").json()["events"]
    assert not any(e["rule_id"] == rule_id and e["client_ip"] == target_ip for e in events)


def test_suppression_scoped_to_client_does_not_affect_others(client, ftl):
    from app import db

    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 1, "window_minutes": 600}})
    rule_id = r.json()["id"]
    clients = db.top_clients(None, limit=5)
    if len(clients) < 2:
        pytest.skip("fixture needs at least 2 clients for this test")
    target_ip, other_ip = clients[0]["ip"], clients[1]["ip"]

    client.post("/api/alert-suppressions", json={"rule_id": rule_id, "client_ip": target_ip})

    events = client.get("/api/alerts").json()["events"]
    assert not any(e["rule_id"] == rule_id and e["client_ip"] == target_ip for e in events)
    assert any(e["rule_id"] == rule_id and e["client_ip"] == other_ip for e in events)


def test_list_and_remove_suppression(client, ftl):
    from app import db

    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 1, "window_minutes": 600}})
    rule_id = r.json()["id"]
    target_ip = next(c["ip"] for c in db.top_clients(None, limit=1))

    created = client.post("/api/alert-suppressions", json={"rule_id": rule_id, "client_ip": target_ip}).json()

    listed = client.get("/api/alert-suppressions").json()
    assert any(s["id"] == created["id"] and s["rule_name"] == "Vol" for s in listed)

    assert client.delete(f"/api/alert-suppressions/{created['id']}").status_code == 200
    assert client.delete(f"/api/alert-suppressions/{created['id']}").status_code == 404
    assert not any(s["id"] == created["id"] for s in client.get("/api/alert-suppressions").json())


def test_deleting_rule_cascades_its_suppressions(client, ftl):
    from app import db

    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 1, "window_minutes": 600}})
    rule_id = r.json()["id"]
    target_ip = next(c["ip"] for c in db.top_clients(None, limit=1))
    client.post("/api/alert-suppressions", json={"rule_id": rule_id, "client_ip": target_ip})

    client.delete(f"/api/alert-rules/{rule_id}")

    assert not any(s["rule_id"] == rule_id for s in client.get("/api/alert-suppressions").json())
