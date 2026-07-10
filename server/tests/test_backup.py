"""Config backup/export (#45) -- GET /api/backup / POST /api/backup/restore.

Backup export/restore is entirely independent of Pi-hole's FTL db (it only
ever touches DNS Watch's own tags/alert_rules/manual_client_names/settings
stores), so these tests don't depend on schema variance the way most of this
suite does -- the `client`/`ftl` fixtures are still used for the API-level
tests purely for the FastAPI TestClient plumbing, not because behavior
differs by schema.
"""

from __future__ import annotations


def test_export_shape(client):
    client.post("/api/tags", json={"name": "kids"})
    client.post("/api/alert-rules", json={
        "name": "Vol", "type": "volume_threshold",
        "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600}})
    client.put("/api/device-names/192.168.1.10", json={"name": "laptop"})

    body = client.get("/api/backup").json()
    assert body["version"] == 1
    assert body["tags"] == [{"name": "kids", "ips": []}]
    assert len(body["alert_rules"]) == 1
    assert body["alert_rules"][0]["name"] == "Vol"
    assert body["alert_rules"][0]["type"] == "volume_threshold"
    assert {"ip": "192.168.1.10", "name": "laptop"} in body["device_names"]
    assert set(body["settings"]) == {"webhook_enabled", "webhook_url", "webhook_format"}


def test_export_never_includes_webhook_secret(client):
    client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": "http://example.test/hook",
        "webhook_secret": "super-secret-token", "webhook_format": "generic"})
    body = client.get("/api/backup").json()
    assert "webhook_secret" not in body["settings"]
    assert "super-secret-token" not in str(body)


def test_export_excludes_alert_events(client):
    client.post("/api/alert-rules", json={
        "name": "New", "type": "new_device", "params": {"window_minutes": 600}})
    client.get("/api/alerts")  # fires at least one event against build_ftl's fixture

    body = client.get("/api/backup").json()
    assert "alert_events" not in body


def test_restore_creates_tag_and_adds_members(client):
    payload = {
        "version": 1,
        "tags": [{"name": "restored-tag", "ips": ["192.168.1.10", "192.168.1.11"]}],
        "alert_rules": [],
        "device_names": [],
        "settings": {},
    }
    r = client.post("/api/backup/restore", json=payload)
    assert r.status_code == 200
    assert r.json()["tags"] == 1

    tags = client.get("/api/tags").json()
    restored = next(t for t in tags if t["name"] == "restored-tag")
    assert set(restored["ips"]) == {"192.168.1.10", "192.168.1.11"}


def test_restore_merges_into_existing_tag_without_duplicating(client):
    tag = client.post("/api/tags", json={"name": "kids"}).json()
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.10"})

    payload = {"tags": [{"name": "kids", "ips": ["192.168.1.10", "192.168.1.11"]}]}
    client.post("/api/backup/restore", json=payload)

    tags = client.get("/api/tags").json()
    assert len(tags) == 1  # merged into the SAME tag, not a duplicate
    assert set(tags[0]["ips"]) == {"192.168.1.10", "192.168.1.11"}


def test_restore_rule_is_idempotent_on_repeat(client):
    payload = {
        "alert_rules": [
            {"name": "Vol", "type": "volume_threshold",
             "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600},
             "enabled": True}
        ]
    }
    r1 = client.post("/api/backup/restore", json=payload)
    assert r1.json()["alert_rules"] == 1

    r2 = client.post("/api/backup/restore", json=payload)
    assert r2.json()["alert_rules"] == 0  # identical rule already exists -- no duplicate

    rules = client.get("/api/alert-rules").json()
    assert len([r for r in rules if r["name"] == "Vol"]) == 1


def test_restore_rule_with_different_params_is_not_deduped(client):
    """A rule with the same name/type but DIFFERENT params must still be
    created -- proves the merge key is the full (name, type, params) triple,
    not just (name, type)."""
    base = {"name": "Vol", "type": "volume_threshold",
            "params": {"scope": "per_client", "threshold": 50, "window_minutes": 600},
            "enabled": True}
    client.post("/api/backup/restore", json={"alert_rules": [base]})

    different = {**base, "params": {**base["params"], "threshold": 999}}
    r = client.post("/api/backup/restore", json={"alert_rules": [different]})
    assert r.json()["alert_rules"] == 1

    rules = [r for r in client.get("/api/alert-rules").json() if r["name"] == "Vol"]
    assert len(rules) == 2


def test_restore_unknown_rule_type_skipped_not_erroring(client):
    payload = {"alert_rules": [{"name": "Future", "type": "not_a_real_type", "params": {}}]}
    r = client.post("/api/backup/restore", json=payload)
    assert r.status_code == 200
    assert r.json()["alert_rules"] == 0


def test_restore_device_names(client):
    payload = {"device_names": [{"ip": "192.168.1.10", "name": "restored-laptop"}]}
    r = client.post("/api/backup/restore", json=payload)
    assert r.json()["device_names"] == 1

    rows = client.get("/api/device-names").json()
    row = next(r for r in rows if r["ip"] == "192.168.1.10")
    assert row["manual_name"] == "restored-laptop"


def test_restore_invalid_device_name_skipped(client):
    payload = {"device_names": [{"ip": "not-an-ip", "name": "whatever"}]}
    r = client.post("/api/backup/restore", json=payload)
    assert r.status_code == 200
    assert r.json()["device_names"] == 0


def test_restore_settings_never_touches_secret(client):
    client.patch("/api/settings", json={
        "webhook_enabled": True, "webhook_url": "http://old.example/hook",
        "webhook_secret": "keep-me", "webhook_format": "generic"})

    payload = {"settings": {"webhook_enabled": True, "webhook_url": "http://new.example/hook",
                             "webhook_format": "slack"}}
    r = client.post("/api/backup/restore", json=payload)
    assert r.json()["settings_restored"] is True

    settings = client.get("/api/settings").json()
    assert settings["webhook_url"] == "http://new.example/hook"
    assert settings["webhook_format"] == "slack"
    # The secret was never in the restore payload (can't be, see backup.py's
    # module note) and must still be set from before.
    assert settings["webhook_secret_set"] is True


def test_restore_round_trip(client):
    """Export -> restore into a fresh store must reproduce the same tags,
    rules, and device names (settings covered separately above)."""
    client.post("/api/tags", json={"name": "roundtrip"})
    client.post(f"/api/tags/{client.get('/api/tags').json()[0]['id']}/members",
                json={"ip": "192.168.1.10"})
    client.post("/api/alert-rules", json={
        "name": "RT", "type": "new_device", "params": {"window_minutes": 100}})
    client.put("/api/device-names/192.168.1.11", json={"name": "rt-phone"})

    exported = client.get("/api/backup").json()

    # Simulate a fresh install by deleting everything the export captured.
    for t in client.get("/api/tags").json():
        client.delete(f"/api/tags/{t['id']}")
    for r in client.get("/api/alert-rules").json():
        client.delete(f"/api/alert-rules/{r['id']}")
    client.delete("/api/device-names/192.168.1.11")

    restore_summary = client.post("/api/backup/restore", json=exported).json()
    assert restore_summary == {
        "tags": 1, "alert_rules": 1, "device_names": 1, "settings_restored": True,
    }

    tags = client.get("/api/tags").json()
    assert len(tags) == 1 and tags[0]["name"] == "roundtrip"
    assert set(tags[0]["ips"]) == {"192.168.1.10"}

    rules = client.get("/api/alert-rules").json()
    assert len(rules) == 1 and rules[0]["name"] == "RT"

    names_rows = client.get("/api/device-names").json()
    row = next(r for r in names_rows if r["ip"] == "192.168.1.11")
    assert row["manual_name"] == "rt-phone"
