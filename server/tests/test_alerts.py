"""Alert engine: rule CRUD, evaluation, cooldown, settings, webhook delivery."""

from __future__ import annotations

import time

# `webhook` fixture lives in conftest.py (shared with test_webhook_security.py).


def _wait(received, before, timeout=5):
    deadline = time.time() + timeout
    while len(received) <= before and time.time() < deadline:
        time.sleep(0.03)


def test_rule_crud(client):
    assert client.get("/api/alert-rules").json() == []
    r = client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600},
    })
    assert r.status_code == 200
    rid = r.json()["id"]
    assert client.patch(f"/api/alert-rules/{rid}", json={"enabled": False}).json()["enabled"] is False
    assert client.patch("/api/alert-rules/9999", json={"enabled": False}).status_code == 404
    assert client.delete(f"/api/alert-rules/{rid}").json() == {"deleted": rid}
    assert client.delete("/api/alert-rules/9999").status_code == 404


def test_invalid_rule_type_rejected(client):
    assert client.post("/api/alert-rules", json={"name": "x", "type": "bogus", "params": {}}).status_code == 400


def test_evaluation_and_cooldown(client):
    client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600}})
    client.post("/api/alert-rules", json={
        "name": "KW", "type": "domain_keyword",
        "params": {"keyword": "ads", "window_minutes": 600, "min_count": 1}})
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})

    a = client.get("/api/alerts").json()
    assert a["new"] > 0
    types = {e["type"] for e in a["events"]}
    assert {"volume_threshold", "domain_keyword", "new_device"} <= types

    # Immediate re-eval fires nothing new (cooldown), event count stable.
    a2 = client.get("/api/alerts").json()
    assert a2["new"] == 0
    assert len(a2["events"]) == len(a["events"])


def test_device_quiet_rule(client, ftl):
    import sqlite3
    from conftest import CLIENTS
    # Add a client that was busy ~90 min ago but silent since -> should trip a
    # device_quiet rule with a 60m window.
    now = int(__import__("time").time())
    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        conn.execute("INSERT INTO client VALUES (98,'192.168.1.98','oldtv')")
        for _ in range(30):
            conn.execute("INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,98)",
                         (now - 90 * 60, 1, 2, "a.example.com"))
    elif ftl["schema"] == "real":
        conn.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (98,'de:ad:be:ef:00:62','TestVendor')")
        conn.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                     "VALUES (98,'192.168.1.98',?,'oldtv',?)", (now, now))
        for _ in range(30):
            conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,'192.168.1.98')",
                         (float(now - 90 * 60), 1, 2, "a.example.com"))
    else:
        conn.execute("INSERT INTO network VALUES (98,'oldtv')")
        conn.execute("INSERT INTO network_addresses VALUES ('192.168.1.98',98)")
        for _ in range(30):
            conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,'192.168.1.98')",
                         (now - 90 * 60, 1, 2, "a.example.com"))
    conn.commit()
    conn.close()

    client.post("/api/alert-rules", json={
        "name": "Quiet", "type": "device_quiet",
        "params": {"window_minutes": 60, "min_prior": 20}})
    events = client.get("/api/alerts").json()["events"]
    quiet = [e for e in events if e["type"] == "device_quiet"]
    assert quiet and any("oldtv" in e["message"] for e in quiet)


def test_settings_roundtrip_and_format_validation(client):
    assert client.get("/api/settings").json()["webhook_enabled"] is False
    updated = client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": "http://x.invalid", "webhook_format": "discord"}).json()
    assert updated["webhook_format"] == "discord" and updated["webhook_enabled"] is True
    assert client.patch("/api/settings", json={"webhook_format": "telegram"}).status_code == 400


def test_test_webhook_success_and_failure(client, webhook):
    url, received = webhook
    r = client.post("/api/settings/test-webhook", json={"url": url, "secret": "tok", "format": "slack"}).json()
    assert r["ok"] is True
    assert received[-1]["body"].keys() == {"text"}          # slack shape
    assert received[-1]["auth"] == "Bearer tok"             # secret -> bearer

    dead = client.post("/api/settings/test-webhook", json={"url": "http://127.0.0.1:1/x"}).json()
    assert dead["ok"] is False and dead["error"]


def test_fire_delivers_webhook_in_format(client, webhook):
    url, received = webhook
    client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": url, "webhook_secret": "s3", "webhook_format": "discord"})
    client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600}})
    before = len(received)
    assert client.get("/api/alerts").json()["new"] > 0
    _wait(received, before)
    assert len(received) > before
    assert received[-1]["body"].keys() == {"content"}       # discord shape
    assert 0 < len(received[-1]["body"]["content"]) <= 2000
    assert received[-1]["auth"] == "Bearer s3"
