"""Data-layer correctness, checked against ground truth on both FTL schemas."""

from __future__ import annotations

from conftest import truth

BLOCKED = {1, 4, 5, 6, 7, 8, 9, 10, 11, 16, 18, 19, 20, 21, 22, 23, 24, 25}
ALLOWED = {2, 3, 12, 13, 17}


def test_summary_matches_ground_truth(ftl):
    from app import db
    rows = truth(ftl["path"]).execute("SELECT status, domain FROM queries").fetchall()
    total = len(rows)
    blocked = sum(1 for r in rows if r["status"] in BLOCKED)
    domains = len({r["domain"] for r in rows})

    s = db.summary(None, None, None)
    assert s["total_queries"] == total
    assert s["blocked"] == blocked
    assert s["unique_domains"] == domains
    assert s["unique_clients"] == 4
    assert s["blocked_pct"] == round(blocked / total * 100, 1)


def test_status_filter_is_sql_not_post_limit(ftl):
    from app import db
    # Ask for 10 blocked with a small limit: must return 10 blocked, not "10
    # rows then filtered down". This is the regression the SQL status filter fixes.
    rows = db.list_queries(None, None, "blocked", None, None, 10, 0)
    assert len(rows) == 10
    assert all(r["status"] == "blocked" for r in rows)


def test_count_matches_list_under_filters(ftl):
    from app import db
    total_blocked = db.count_queries(None, None, "blocked", None, None)
    all_blocked = db.list_queries(None, None, "blocked", None, None, 10_000, 0)
    assert total_blocked == len(all_blocked)

    dl = db.list_queries(None, "ads", None, None, None, 10_000, 0)
    assert db.count_queries(None, "ads", None, None, None) == len(dl)


def test_client_filter_aggregate(ftl):
    from app import db
    conn = truth(ftl["path"])
    if ftl["schema"] == "new":
        q = ("SELECT COUNT(*) n FROM queries q "
             "LEFT JOIN client c ON c.id=q.client_id WHERE c.ip=?")
    else:
        q = "SELECT COUNT(*) n FROM queries q WHERE q.client=?"
    expected = conn.execute(q, ("192.168.1.10",)).fetchone()["n"]
    s = db.summary("192.168.1.10", None, None)
    assert s["total_queries"] == expected
    assert s["unique_clients"] == 1
    assert db.count_queries("192.168.1.10", None, None, None, None) == expected


def test_timeseries_conserves_totals(ftl):
    from app import db
    rows = truth(ftl["path"]).execute("SELECT status FROM queries").fetchall()
    total = len(rows)
    allowed = sum(1 for r in rows if r["status"] in ALLOWED)
    blocked = sum(1 for r in rows if r["status"] in BLOCKED)

    ts = db.timeseries(None, None, None, buckets=30)
    series = ts["series"]
    assert sum(p["total"] for p in series) == total
    assert sum(p["allowed"] for p in series) == allowed
    assert sum(p["blocked"] for p in series) == blocked
    assert ts["bucket_seconds"] > 0
    assert all(series[i]["t"] < series[i + 1]["t"] for i in range(len(series) - 1))


def test_query_types_sum(ftl):
    from app import db
    total = truth(ftl["path"]).execute("SELECT COUNT(*) n FROM queries").fetchone()["n"]
    qt = db.query_types(None, None)
    assert sum(x["count"] for x in qt) == total
    assert all(x["type"] for x in qt)  # every code resolves to a label


def test_client_activity_sparkline_sums(ftl):
    from app import db
    ca = db.client_activity(None, None, limit=10, buckets=20)
    assert len(ca) == 4
    for c in ca:
        assert sum(c["sparkline"]) == c["count"]
        assert c["first_seen"] is not None and c["last_seen"] is not None


def test_new_clients_cutoff(ftl):
    from app import db
    import time
    # All synthetic data is within the last hour, so a 2h cutoff catches all 4
    # clients; a cutoff in the future catches none.
    now = int(time.time())
    assert len(db.new_clients(now - 7200)) == 4
    assert db.new_clients(now + 3600) == []
