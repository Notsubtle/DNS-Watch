"""DNS-tunneling/exfiltration detector (`db.tunneling_candidates` /
`GET /api/tunneling-candidates`, #2) -- one client emitting an unusually high
number of distinct subdomains under a single registered parent domain.

The core correctness property under test: grouping is PSL-aware (registered
parent, not naive last-two-labels), and the threshold is per-(client, parent),
not a flat per-client subdomain count across unrelated parents.
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


def test_high_cardinality_client_flagged(ftl):
    from app import db

    now = int(time.time())
    ip = CLIENTS[0][0]
    for i in range(30):
        _insert(ftl, f"chunk{i}.tunnel.example.test", ip, now - 60 - i)

    results = db.tunneling_candidates(now - 3600, now + 1, min_distinct=20, limit=50)
    hit = next((r for r in results if r["ip"] == ip and r["parent_domain"] == "example.test"), None)
    assert hit is not None
    assert hit["distinct_subdomains"] == 30
    assert hit["query_count"] == 30
    assert len(hit["sample_subdomains"]) == 5


def test_below_threshold_not_flagged(ftl):
    from app import db

    now = int(time.time())
    ip = CLIENTS[0][0]
    for i in range(5):
        _insert(ftl, f"chunk{i}.small.example.test", ip, now - 60 - i)

    results = db.tunneling_candidates(now - 3600, now + 1, min_distinct=20, limit=50)
    assert not any(r["parent_domain"] == "small.example.test" for r in results)


def test_registered_parent_grouping_is_psl_aware(ftl):
    """A multi-part suffix (co.uk) must not be mistaken for the registered
    parent itself -- subdomains under "tunnel.example.co.uk" must group under
    "example.co.uk", not the bare "co.uk" suffix shared by unrelated domains."""
    from app import db

    now = int(time.time())
    ip = CLIENTS[0][0]
    for i in range(25):
        _insert(ftl, f"chunk{i}.tunnel.example.co.uk", ip, now - 60 - i)
    # Unrelated domain sharing the same public suffix must NOT be folded in.
    _insert(ftl, "unrelated.other.co.uk", ip, now - 60)

    results = db.tunneling_candidates(now - 3600, now + 1, min_distinct=20, limit=50)
    hit = next((r for r in results if r["ip"] == ip and r["parent_domain"] == "example.co.uk"), None)
    assert hit is not None
    assert hit["distinct_subdomains"] == 25
    assert not any(r["parent_domain"] == "co.uk" for r in results)


def test_api_tunneling_candidates_shape(client, ftl):
    resp = client.get("/api/tunneling-candidates", params={"range": "1h"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_tunneling_candidates_validates_params(client, ftl):
    assert client.get("/api/tunneling-candidates", params={"min_distinct": 0}).status_code == 422
    assert client.get("/api/tunneling-candidates", params={"limit": 0}).status_code == 422
