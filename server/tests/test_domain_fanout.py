"""Cross-client domain fan-out (`db.domain_fanout` / `GET /api/domain-fanout`,
#34) — "which domains got hit by several distinct clients within the same
SHORT window", surfacing synchronized beaconing a per-client view can't show.

The core correctness property under test: clustering in TIME is what
qualifies a domain, not just having many distinct clients somewhere in the
overall range -- a domain hit by every client but spread across the whole
window must NOT qualify, since that's the exact "CDN/ad domain everyone
legitimately hits" false-positive both product-review scopings for this
issue flagged.
"""

from __future__ import annotations

import sqlite3
import time

from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id


def _insert(ftl, domain: str, ip: str, ts: float) -> None:
    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == ip)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, domain, cid),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        name = next(n for cip, n in CLIENTS if cip == ip)
        cid = _idstore_client_id(cur, ip, name)
        did = _idstore_domain_id(cur, domain)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (int(ts), 1, 2, did, cid),
        )
    else:  # "old" / "real"
        stored_ts = float(ts) if ftl["schema"] == "real" else int(ts)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (stored_ts, 1, 2, domain, ip),
        )
    conn.commit()
    conn.close()


def test_clustered_burst_qualifies(ftl):
    """Three distinct clients hitting the same brand-new domain within a
    single 5-minute bucket must be surfaced, with the correct client list."""
    from app import db

    now = int(time.time())
    domain = "beacon.example.test"
    ips = [c[0] for c in CLIENTS[:3]]
    for i, ip in enumerate(ips):
        # Offset well clear of `since`'s own bucket boundary (since = now -
        # 3600, an exact multiple of the 300s bucket size) -- a burst placed
        # right at that edge could itself straddle two buckets, which is a
        # real property of fixed-window bucketing (see domain_fanout's
        # docstring), not what this test is trying to exercise.
        _insert(ftl, domain, ip, now - 1830 - i)  # all within the same few seconds

    results = db.domain_fanout(now - 3600, now + 1, bucket_minutes=5, min_clients=3, limit=1000)
    hit = next((r for r in results if r["domain"] == domain), None)
    assert hit is not None, "clustered 3-client burst should qualify"
    assert hit["client_count"] == 3
    assert hit["query_count"] == 3
    assert {c["ip"] for c in hit["clients"]} == set(ips)


def test_spread_out_hits_do_not_qualify(ftl):
    """The SAME 3 clients hitting the same domain, but each in a DIFFERENT
    5-minute bucket (spread far apart), must NOT qualify -- proves this is
    genuinely about temporal clustering, not "3+ distinct clients somewhere
    in the whole range" (which every popular CDN domain would trivially and
    constantly satisfy)."""
    from app import db

    now = int(time.time())
    domain = "spread-out.example.test"
    ips = [c[0] for c in CLIENTS[:3]]
    # 20 minutes apart -- well outside any single 5-minute bucket.
    for i, ip in enumerate(ips):
        _insert(ftl, domain, ip, now - i * 1200)

    results = db.domain_fanout(now - 3600, now + 1, bucket_minutes=5, min_clients=3, limit=1000)
    assert not any(r["domain"] == domain for r in results)


def test_min_clients_threshold_respected(ftl):
    """Two clustered clients must not qualify a min_clients=3 rule, but do
    qualify once the threshold is lowered to 2."""
    from app import db

    now = int(time.time())
    domain = "two-clients.example.test"
    ips = [c[0] for c in CLIENTS[:2]]
    for i, ip in enumerate(ips):
        # Offset well clear of `since`'s own bucket boundary (since = now -
        # 3600, an exact multiple of the 300s bucket size) -- a burst placed
        # right at that edge could itself straddle two buckets, which is a
        # real property of fixed-window bucketing (see domain_fanout's
        # docstring), not what this test is trying to exercise.
        _insert(ftl, domain, ip, now - 1830 - i)

    assert not any(
        r["domain"] == domain
        for r in db.domain_fanout(now - 3600, now + 1, bucket_minutes=5, min_clients=3, limit=1000)
    )
    assert any(
        r["domain"] == domain
        for r in db.domain_fanout(now - 3600, now + 1, bucket_minutes=5, min_clients=2, limit=1000)
    )


def test_api_domain_fanout(client, ftl):
    """End-to-end through the FastAPI route, including query-param bounds."""
    now = int(time.time())
    domain = "api-beacon.example.test"
    ips = [c[0] for c in CLIENTS[:3]]
    for i, ip in enumerate(ips):
        # Offset well clear of `since`'s own bucket boundary (since = now -
        # 3600, an exact multiple of the 300s bucket size) -- a burst placed
        # right at that edge could itself straddle two buckets, which is a
        # real property of fixed-window bucketing (see domain_fanout's
        # docstring), not what this test is trying to exercise.
        _insert(ftl, domain, ip, now - 1830 - i)

    r = client.get(
        "/api/domain-fanout",
        params={"range": "1h", "bucket_minutes": 5, "min_clients": 3, "limit": 200},
    )
    assert r.status_code == 200
    body = r.json()
    hit = next((row for row in body if row["domain"] == domain), None)
    assert hit is not None
    assert hit["client_count"] == 3
    assert len(hit["clients"]) == 3

    # Out-of-bounds params are rejected server-side, not silently clamped.
    assert client.get("/api/domain-fanout", params={"min_clients": 1}).status_code == 422
    assert client.get("/api/domain-fanout", params={"bucket_minutes": 0}).status_code == 422
