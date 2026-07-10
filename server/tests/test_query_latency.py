"""Query resolution latency ranking (`db.slowest_domains` / `GET
/api/query-latency`, #47) -- domains ranked by average `reply_time` (Pi-hole's
own per-query resolution latency, in seconds) over a range, surfacing slow,
uncached, or upstream-forwarded lookups a per-client view can't show.

Only meaningful on the normalized (has_id_storage) schema -- reply_time
doesn't exist on the older layouts at all (verified against every schema
variant this app supports; see slowest_domains' module note on the real
UAT snapshot finding that ruled out a DNSSEC/EDE alert rule).
"""

from __future__ import annotations

import sqlite3
import time

from conftest import _idstore_client_id, _idstore_domain_id


def _insert_with_reply_time(ftl, domain: str, reply_time: float, ts: float) -> None:
    conn = sqlite3.connect(ftl["path"])
    cur = conn.cursor()
    cid = _idstore_client_id(cur, "192.168.1.10", "laptop")
    did = _idstore_domain_id(cur, domain)
    conn.execute(
        "INSERT INTO query_storage (timestamp,type,status,domain,client,reply_time) "
        "VALUES (?,?,?,?,?,?)",
        (int(ts), 1, 2, did, cid, reply_time),
    )
    conn.commit()
    conn.close()


def test_returns_empty_without_reply_time_column(ftl):
    """"new"/"old"/"real" schemas carry no reply_time column at all -- must
    return [] rather than erroring, matching has_vendor_data's precedent."""
    from app import db

    if ftl["schema"] != "idstore":
        assert db.slowest_domains(None, None) == []


def test_ranks_by_average_reply_time(ftl):
    from app import db

    if ftl["schema"] != "idstore":
        return

    now = int(time.time())
    # 5 hits each, well above the default min_count -- fast domain first so a
    # naive "first row wins" bug would be caught by the ordering assertion.
    for i in range(5):
        _insert_with_reply_time(ftl, "fast.example.test", 0.001, now - i)
        _insert_with_reply_time(ftl, "slow.example.test", 0.5, now - i)

    result = db.slowest_domains(now - 3600, now + 1, min_count=5, limit=10)
    domains = [r["domain"] for r in result]
    assert domains.index("slow.example.test") < domains.index("fast.example.test")
    slow = next(r for r in result if r["domain"] == "slow.example.test")
    assert slow["avg_reply_ms"] == 500.0
    assert slow["query_count"] == 5


def test_min_count_filters_single_outlier(ftl):
    """A domain queried once at a high latency shouldn't dominate the ranking
    over one that's consistently (if more moderately) slow across many hits."""
    from app import db

    if ftl["schema"] != "idstore":
        return

    now = int(time.time())
    _insert_with_reply_time(ftl, "one-off-spike.example.test", 5.0, now)
    for i in range(5):
        _insert_with_reply_time(ftl, "consistently-slow.example.test", 0.3, now - i)

    result = db.slowest_domains(now - 3600, now + 1, min_count=5, limit=10)
    domains = {r["domain"] for r in result}
    assert "consistently-slow.example.test" in domains
    assert "one-off-spike.example.test" not in domains


def test_api_query_latency(client, ftl):
    if ftl["schema"] != "idstore":
        r = client.get("/api/query-latency", params={"range": "1h"})
        assert r.status_code == 200
        assert r.json() == []
        return

    now = int(time.time())
    for i in range(5):
        _insert_with_reply_time(ftl, "slow-api.example.test", 0.25, now - i)

    r = client.get("/api/query-latency", params={"range": "1h", "min_count": 5})
    assert r.status_code == 200
    body = r.json()
    hit = next((row for row in body if row["domain"] == "slow-api.example.test"), None)
    assert hit is not None
    assert hit["query_count"] == 5
