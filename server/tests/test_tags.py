"""Client tags/groups (#31): CRUD, membership, and API surface."""

from __future__ import annotations


def test_tag_crud(client):
    assert client.get("/api/tags").json() == []

    r = client.post("/api/tags", json={"name": "IoT"})
    assert r.status_code == 200
    tag = r.json()
    assert tag["name"] == "IoT"
    assert tag["ips"] == []
    tag_id = tag["id"]

    assert client.post("/api/tags", json={"name": "IoT"}).status_code == 400  # duplicate name
    assert client.post("/api/tags", json={"name": "  "}).status_code == 400  # blank

    r = client.post(f"/api/tags/{tag_id}/members", json={"ip": "192.168.1.10"})
    assert r.status_code == 200
    r = client.post(f"/api/tags/{tag_id}/members", json={"ip": "192.168.1.11"})
    assert r.status_code == 200
    # Adding the same member twice is idempotent, not an error.
    assert client.post(f"/api/tags/{tag_id}/members", json={"ip": "192.168.1.10"}).status_code == 200

    listed = client.get("/api/tags").json()
    assert len(listed) == 1
    assert sorted(listed[0]["ips"]) == ["192.168.1.10", "192.168.1.11"]

    assert client.post("/api/tags/9999/members", json={"ip": "1.2.3.4"}).status_code == 404

    assert client.delete(f"/api/tags/{tag_id}/members/192.168.1.10").status_code == 200
    assert client.delete(f"/api/tags/{tag_id}/members/192.168.1.10").status_code == 404  # already gone
    assert client.get("/api/tags").json()[0]["ips"] == ["192.168.1.11"]

    assert client.delete(f"/api/tags/{tag_id}").json() == {"deleted": tag_id}
    assert client.delete(f"/api/tags/{tag_id}").status_code == 404
    assert client.get("/api/tags").json() == []


def test_deleting_tag_cascades_membership(client):
    """Deleting a tag removes its membership rows too (the FK's ON DELETE
    CASCADE), so a stale tag_id never lingers in client_tag_members."""
    from app import tags

    tag = client.post("/api/tags", json={"name": "Guest"}).json()
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "10.0.0.5"})
    client.delete(f"/api/tags/{tag['id']}")

    # Re-creating a tag with the same name must not resurrect the old
    # membership under a reused/new id.
    new_tag = client.post("/api/tags", json={"name": "Guest"}).json()
    assert new_tag["ips"] == []
    assert tags.get_tag_ips("Guest") == []


def test_get_tag_ips_distinguishes_unknown_from_empty():
    from app import tags

    assert tags.get_tag_ips("does-not-exist") is None
    tags.create_tag("Empty")
    assert tags.get_tag_ips("Empty") == []


def test_api_endpoints_accept_tag_param(client, ftl):
    """#31: the dashboard's client-filterable endpoints accept `tag=` as an
    alternative to `client=`, scoped to the tag's members. Compares against
    the same two-ip filter applied directly via `client=` twice (there's no
    multi-client query syntax over HTTP, so summing the two solo calls is the
    ground truth) -- and an unknown tag name 404s rather than silently
    matching everything."""
    tag = client.post("/api/tags", json={"name": "Laptops"}).json()
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.10"})
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.11"})

    solo_total = sum(
        client.get("/api/summary", params={"client": ip, "range": "all"}).json()["total_queries"]
        for ip in ("192.168.1.10", "192.168.1.11")
    )
    tagged = client.get("/api/summary", params={"tag": "Laptops", "range": "all"}).json()
    assert tagged["total_queries"] == solo_total

    r = client.get("/api/queries", params={"tag": "Laptops", "range": "all", "limit": 1000})
    assert r.status_code == 200
    assert r.json()["total"] == solo_total

    assert client.get("/api/summary", params={"tag": "no-such-tag"}).status_code == 404
