"""Vendor-based client filtering (#11 remaining scope) — a resolved vendor
(Pi-hole's own macVendor, or the offline OUI fallback) re-scopes the whole
dashboard to every client of that vendor at once, the same way a tag (#31)
already does. Unlike a tag, a vendor isn't a stored/nameable entity a user
creates: `db.list_vendors()`/`db.client_ips_for_vendor()` derive it live from
whatever clients currently resolve to that vendor string.
"""

from __future__ import annotations

import sqlite3

from conftest import CLIENTS


def _set_vendor(ftl, ip: str, vendor: str) -> None:
    """Overwrite one client's resolved vendor in the fixture's `network`
    table. Only meaningful on schemas with vendor data at all ("real",
    "idstore") -- build_ftl() gives every CLIENTS entry the same
    "TestVendor" by default, so tests that need to tell clients apart by
    vendor must first split them into distinct groups."""
    conn = sqlite3.connect(ftl["path"])
    conn.execute(
        "UPDATE network SET macVendor = ? "
        "WHERE id = (SELECT network_id FROM network_addresses WHERE ip = ?)",
        (vendor, ip),
    )
    conn.commit()
    conn.close()


def test_list_vendors_empty_without_vendor_data(ftl):
    """"old"/"new" schemas carry no network/macVendor data at all -- must
    return [] rather than erroring, matching has_vendor_data's other call
    sites (_client_vendor_map, vendor_alert_candidates)."""
    from app import db

    if ftl["schema"] in ("old", "new"):
        assert db.list_vendors() == []
        assert db.client_ips_for_vendor("anything") == []


def test_list_vendors_groups_by_resolved_vendor(ftl):
    """On a schema with vendor data, splitting the 4 standard CLIENTS into two
    vendors must produce two correctly-populated groups, sorted by name."""
    from app import db

    if ftl["schema"] not in ("real", "idstore"):
        return

    ips = [c[0] for c in CLIENTS]
    _set_vendor(ftl, ips[0], "Acme Corp")
    _set_vendor(ftl, ips[1], "Acme Corp")
    _set_vendor(ftl, ips[2], "Zenith Inc")
    _set_vendor(ftl, ips[3], "Zenith Inc")

    vendors = db.list_vendors()
    by_name = {v["name"]: set(v["ips"]) for v in vendors}
    assert by_name["Acme Corp"] == {ips[0], ips[1]}
    assert by_name["Zenith Inc"] == {ips[2], ips[3]}
    # Sorted by name -- deterministic dropdown order in the frontend.
    assert [v["name"] for v in vendors] == sorted(by_name)


def test_client_ips_for_vendor(ftl):
    from app import db

    if ftl["schema"] not in ("real", "idstore"):
        return

    ips = [c[0] for c in CLIENTS]
    _set_vendor(ftl, ips[0], "Acme Corp")
    _set_vendor(ftl, ips[1], "Zenith Inc")

    assert db.client_ips_for_vendor("Acme Corp") == [ips[0]]
    # Unmatched vendor name -- silently matches nothing, no error, same as an
    # unrecognized single client ip already does in _build_where.
    assert db.client_ips_for_vendor("Nonexistent Vendor") == []


def test_api_vendor_filter_scopes_dashboard(client, ftl):
    """End-to-end: /api/summary?vendor=... must scope to exactly that
    vendor's clients, and an unmatched vendor name must 200 with an
    empty-matching result rather than 404ing (unlike an unknown tag name)."""
    if ftl["schema"] not in ("real", "idstore"):
        return

    ips = [c[0] for c in CLIENTS]
    _set_vendor(ftl, ips[0], "Acme Corp")
    for other_ip in ips[1:]:
        _set_vendor(ftl, other_ip, "Zenith Inc")

    r = client.get("/api/vendors")
    assert r.status_code == 200
    names = {v["name"] for v in r.json()}
    assert names == {"Acme Corp", "Zenith Inc"}

    all_summary = client.get("/api/summary", params={"range": "all"}).json()
    scoped_summary = client.get(
        "/api/summary", params={"range": "all", "vendor": "Acme Corp"}
    ).json()
    assert scoped_summary["total_queries"] <= all_summary["total_queries"]

    # An ip-scoped query for the single Acme client must match the
    # vendor-scoped query exactly, since Acme Corp has only that one member.
    ip_scoped = client.get(
        "/api/summary", params={"range": "all", "client": ips[0]}
    ).json()
    assert scoped_summary["total_queries"] == ip_scoped["total_queries"]

    unmatched = client.get(
        "/api/summary", params={"range": "all", "vendor": "Nonexistent Vendor"}
    )
    assert unmatched.status_code == 200
    assert unmatched.json()["total_queries"] == 0
