"""Dashboard-wide blocked-domain ranking per client."""

from __future__ import annotations

import sqlite3

import pytest

from conftest import _idstore_client_id, _idstore_domain_id, _idstore_schema


BLOCKED = 1
ALLOWED = 2
NOW = 2_000
OLD = 100


def _clear_queries(conn: sqlite3.Connection, schema: str) -> None:
    if schema == "idstore":
        conn.execute("DELETE FROM query_storage")
    else:
        conn.execute("DELETE FROM queries")


def _insert_query(
    conn: sqlite3.Connection,
    schema: str,
    ts: int,
    ip: str,
    name: str | None,
    domain: str,
    status: int,
) -> None:
    cur = conn.cursor()
    if schema == "new":
        cid = conn.execute("SELECT id FROM client WHERE ip = ?", (ip,)).fetchone()[0]
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (ts, 1, status, domain, cid),
        )
        return
    if schema == "idstore":
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (ts, 1, status, did, cid),
        )
        return
    conn.execute(
        "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
        (float(ts) if schema == "real" else ts, 1, status, domain, ip),
    )


def _seed_blocked_fixture(path: str, schema: str) -> None:
    conn = sqlite3.connect(path)
    _clear_queries(conn, schema)
    rows = [
        ("192.168.1.10", "laptop", "ads.example.com", BLOCKED, 3),
        ("192.168.1.10", "laptop", "tracker.bad.co", BLOCKED, 2),
        ("192.168.1.10", "laptop", "ads.example.com", ALLOWED, 4),
        ("192.168.1.11", "phone", "ads.example.com", BLOCKED, 4),
        ("192.168.1.12", "tv", "cdn.site.net", ALLOWED, 5),
        ("192.168.1.13", None, "ads.example.com", BLOCKED, 2),
        ("192.168.1.11", "phone", "old.example.com", BLOCKED, 9),
    ]
    for ip, name, domain, status, count in rows:
        ts = OLD if domain == "old.example.com" else NOW
        for _ in range(count):
            _insert_query(conn, schema, ts, ip, name, domain, status)
    conn.commit()
    conn.close()


@pytest.fixture
def blocked_ftl(ftl):
    _seed_blocked_fixture(ftl["path"], ftl["schema"])
    return ftl


def _by_pair(rows):
    return {(r["client_ip"], r["domain"]): r for r in rows}


def test_top_blocked_per_client_ranking_and_status_filter(blocked_ftl):
    from app import db

    rows = db.top_blocked_per_client(None, since=1_000, limit=10)
    by_pair = _by_pair(rows)

    assert [r["blocked_count"] for r in rows[:2]] == [4, 3]
    assert by_pair[("192.168.1.11", "ads.example.com")]["blocked_count"] == 4
    assert by_pair[("192.168.1.10", "ads.example.com")]["blocked_count"] == 3
    assert by_pair[("192.168.1.10", "tracker.bad.co")]["blocked_count"] == 2
    assert by_pair[("192.168.1.13", "ads.example.com")]["client_name"] is None
    assert ("192.168.1.12", "cdn.site.net") not in by_pair
    assert ("192.168.1.11", "old.example.com") not in by_pair


def test_top_blocked_per_client_limit_and_client_filters(blocked_ftl):
    from app import db

    assert len(db.top_blocked_per_client(None, since=1_000, limit=2)) == 2

    single = _by_pair(db.top_blocked_per_client("192.168.1.10", since=1_000, limit=10))
    assert set(single) == {
        ("192.168.1.10", "ads.example.com"),
        ("192.168.1.10", "tracker.bad.co"),
    }

    tagged = _by_pair(
        db.top_blocked_per_client(["192.168.1.10", "192.168.1.13"], since=1_000, limit=10)
    )
    assert set(tagged) == {
        ("192.168.1.10", "ads.example.com"),
        ("192.168.1.10", "tracker.bad.co"),
        ("192.168.1.13", "ads.example.com"),
    }


def test_top_blocked_per_client_endpoint_filters_and_shape(client, ftl):
    _seed_blocked_fixture(ftl["path"], ftl["schema"])

    tag = client.post("/api/tags", json={"name": "BlockedGroup"}).json()
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.10"})
    client.post(f"/api/tags/{tag['id']}/members", json={"ip": "192.168.1.13"})

    r = client.get(
        "/api/top-blocked-per-client",
        params={"tag": "BlockedGroup", "range": "all", "since": 1_000, "limit": 10},
    )
    assert r.status_code == 200
    rows = r.json()
    assert {"client_ip", "client_name", "domain", "blocked_count"} <= set(rows[0])
    assert {tuple((x["client_ip"], x["domain"])) for x in rows} == {
        ("192.168.1.10", "ads.example.com"),
        ("192.168.1.10", "tracker.bad.co"),
        ("192.168.1.13", "ads.example.com"),
    }


def test_top_blocked_per_client_idstore_merges_duplicate_client_ids(tmp_path, monkeypatch):
    from app import db

    path = str(tmp_path / "pihole-FTL.db")
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    _idstore_schema(cur)
    cid_a = _idstore_client_id(cur, "127.0.0.1", "")
    cid_b = _idstore_client_id(cur, "127.0.0.1", "localhost")
    did = _idstore_domain_id(cur, "ads.example.com")
    for cid, count in ((cid_a, 2), (cid_b, 3)):
        for _ in range(count):
            conn.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (NOW, 1, BLOCKED, did, cid),
            )
    conn.commit()
    conn.close()

    monkeypatch.setattr(db, "DB_PATH", path)
    db.detect_schema.cache_clear()
    try:
        assert db.top_blocked_per_client(None, since=1_000, limit=10) == [
            {
                "client_ip": "127.0.0.1",
                "client_name": None,
                "domain": "ads.example.com",
                "blocked_count": 5,
            }
        ]
    finally:
        db.detect_schema.cache_clear()
