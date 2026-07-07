"""Manual client naming (names.py) — the user's own override, and its
precedence over Pi-hole's name / resolve.py's rDNS cache in db._display_name,
plus the /api/device-names CRUD endpoints."""

from __future__ import annotations

import pytest

from app import names


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(names, "STORE_PATH", str(tmp_path / "names.db"))


def test_set_and_get_name():
    names.set_name("192.168.1.10", "Steve's Laptop")
    assert names.get_names() == {"192.168.1.10": "Steve's Laptop"}


def test_set_name_strips_whitespace():
    names.set_name("192.168.1.10", "  Fridge  ")
    assert names.get_names()["192.168.1.10"] == "Fridge"


def test_set_name_upserts():
    names.set_name("192.168.1.10", "Old Name")
    names.set_name("192.168.1.10", "New Name")
    assert names.get_names() == {"192.168.1.10": "New Name"}


def test_set_name_rejects_blank():
    with pytest.raises(names.InvalidName):
        names.set_name("192.168.1.10", "   ")


def test_set_name_rejects_too_long():
    with pytest.raises(names.InvalidName):
        names.set_name("192.168.1.10", "x" * (names.MAX_NAME_LENGTH + 1))


def test_set_name_rejects_invalid_ip():
    with pytest.raises(names.InvalidName):
        names.set_name("not-an-ip", "Fridge")


def test_delete_name_returns_true_when_removed():
    names.set_name("192.168.1.10", "Fridge")
    assert names.delete_name("192.168.1.10") is True
    assert names.get_names() == {}


def test_delete_name_returns_false_when_absent():
    assert names.delete_name("192.168.1.99") is False


def test_list_names_includes_timestamps():
    names.set_name("192.168.1.10", "Fridge")
    [row] = names.list_names()
    assert row["ip"] == "192.168.1.10"
    assert row["name"] == "Fridge"
    assert row["created_at"] > 0
    assert row["updated_at"] > 0


def test_display_name_manual_override_wins_over_everything(monkeypatch):
    from app import db
    assert db._display_name("Pi-hole Name", "192.168.1.10", {"192.168.1.10": "rdns.lan"},
                             {"192.168.1.10": "My Override"}) == "My Override"


def test_display_name_falls_back_without_manual_override():
    from app import db
    assert db._display_name("Pi-hole Name", "192.168.1.10", {}, {}) == "Pi-hole Name"
    assert db._display_name(None, "192.168.1.10", {"192.168.1.10": "rdns.lan"}, {}) == "rdns.lan"
    assert db._display_name(None, "192.168.1.10", {}, {}) == "192.168.1.10"


def test_api_list_device_names_reflects_manual_override(client, ftl):
    # CLIENTS[3] = ("192.168.1.13", None) in conftest.py — unnamed by Pi-hole.
    resp = client.put("/api/device-names/192.168.1.13", json={"name": "Smart Fridge"})
    assert resp.status_code == 200

    rows = {r["ip"]: r for r in client.get("/api/device-names").json()}
    assert rows["192.168.1.13"]["manual_name"] == "Smart Fridge"
    assert rows["192.168.1.13"]["display_name"] == "Smart Fridge"
    assert rows["192.168.1.13"]["seen"] is True

    # And it propagates to the ordinary client list, not just the manage-UI endpoint.
    client_rows = {c["ip"]: c for c in client.get("/api/clients").json()}
    assert client_rows["192.168.1.13"]["name"] == "Smart Fridge"


def test_api_set_device_name_rejects_invalid_name(client, ftl):
    resp = client.put("/api/device-names/192.168.1.13", json={"name": ""})
    assert resp.status_code == 400


def test_api_delete_device_name(client, ftl):
    client.put("/api/device-names/192.168.1.13", json={"name": "Smart Fridge"})
    assert client.delete("/api/device-names/192.168.1.13").status_code == 200
    rows = {r["ip"]: r for r in client.get("/api/device-names").json()}
    assert rows["192.168.1.13"]["manual_name"] is None


def test_api_delete_unknown_device_name_404s(client, ftl):
    resp = client.delete("/api/device-names/10.0.0.99")
    assert resp.status_code == 404


def test_api_device_names_includes_stale_manual_only_entries(client, ftl):
    """A manual name for an ip with no current Pi-hole traffic must stay
    visible (and deletable) rather than silently disappearing."""
    resp = client.put("/api/device-names/10.0.0.250", json={"name": "Old Printer"})
    assert resp.status_code == 200

    rows = {r["ip"]: r for r in client.get("/api/device-names").json()}
    assert rows["10.0.0.250"]["manual_name"] == "Old Printer"
    assert rows["10.0.0.250"]["seen"] is False
    assert rows["10.0.0.250"]["query_count"] == 0
