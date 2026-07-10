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


def test_vendor_oui_fallback_and_randomized_mac(ftl):
    """#5: when Pi-hole's own macVendor is empty, DNS Watch falls back to its
    offline OUI table for a real, listed prefix — and labels a
    locally-administered (randomized/private) MAC distinctly rather than
    treating it as a plain miss. Only "real"/"idstore" schemas have a
    `network` table with hwaddr/macVendor at all (see #4)."""
    if ftl["schema"] not in ("real", "idstore"):
        return
    import sqlite3
    from app import db

    conn = sqlite3.connect(ftl["path"])
    # 00:00:01:.. is a real, listed IEEE MA-L prefix (Xerox) — clear Pi-hole's
    # own macVendor so the OUI-table fallback is what actually resolves it.
    conn.execute(
        "UPDATE network SET hwaddr = '00:00:01:aa:bb:cc', macVendor = '' "
        "WHERE id = (SELECT network_id FROM network_addresses WHERE ip = ?)",
        ("192.168.1.10",),
    )
    # 02:.. has the locally-administered bit set — a randomized/private MAC,
    # which has no vendor in any registry by design.
    conn.execute(
        "UPDATE network SET hwaddr = '02:11:22:33:44:55', macVendor = '' "
        "WHERE id = (SELECT network_id FROM network_addresses WHERE ip = ?)",
        ("192.168.1.11",),
    )
    conn.commit()
    conn.close()

    clients = {c["ip"]: c for c in db.list_clients()}
    xerox = clients["192.168.1.10"]
    assert xerox["mac_known"] is True
    assert xerox["vendor"] == "XEROX CORPORATION"
    assert xerox["vendor_unknown_reason"] is None

    randomized = clients["192.168.1.11"]
    assert randomized["mac_known"] is True
    assert randomized["vendor"] is None
    assert randomized["vendor_unknown_reason"] == "randomized"


def test_vendor_alert_candidates(ftl):
    """#12: db.vendor_alert_candidates() backs the new_vendor alert rule.
    Uses an exact after_ts cutoff (rather than going through the alert rule's
    minute-granularity window) so which of build_ftl's standard clients count
    as "new" is deterministic, not dependent on its random first-seen offsets."""
    from app import db

    if ftl["schema"] not in ("real", "idstore"):
        # No vendor table at all on this schema (#4) -- must be a no-op, not
        # a false "every device looks unrecognized" signal from the data gap.
        assert db.vendor_alert_candidates(0) == []
        return

    import sqlite3
    conn = sqlite3.connect(ftl["path"])
    cutoff = int(conn.execute("SELECT MAX(timestamp) FROM " + (
        "query_storage" if ftl["schema"] == "idstore" else "queries"
    )).fetchone()[0]) + 1

    if ftl["schema"] == "real":
        # Already-established vendor, but a genuinely NEW client of it --
        # must not be flagged (this vendor already exists on the network).
        conn.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (98,'de:ad:be:ef:00:98','TestVendor')")
        conn.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                     "VALUES (98,'192.168.1.98',?,NULL,?)", (cutoff, cutoff))
        conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (float(cutoff), 1, 2, "z.example.com", "192.168.1.98"))
        # Genuinely new vendor.
        conn.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (99,'aa:bb:cc:dd:ee:99','NewCo')")
        conn.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                     "VALUES (99,'192.168.1.99',?,NULL,?)", (cutoff, cutoff))
        conn.execute("INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (float(cutoff), 1, 2, "y.example.com", "192.168.1.99"))
    else:
        from conftest import _idstore_client_id, _idstore_domain_id
        cur = conn.cursor()
        cid_established = _idstore_client_id(cur, "192.168.1.98", None)
        conn.execute(
            "UPDATE network SET hwaddr='de:ad:be:ef:00:98', macVendor='TestVendor' WHERE id = "
            "(SELECT network_id FROM network_addresses WHERE ip='192.168.1.98')"
        )
        did = _idstore_domain_id(cur, "z.example.com")
        conn.execute("INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (cutoff, 1, 2, did, cid_established))

        cid_new = _idstore_client_id(cur, "192.168.1.99", None)
        conn.execute(
            "UPDATE network SET hwaddr='aa:bb:cc:dd:ee:99', macVendor='NewCo' WHERE id = "
            "(SELECT network_id FROM network_addresses WHERE ip='192.168.1.99')"
        )
        did2 = _idstore_domain_id(cur, "y.example.com")
        conn.execute("INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                     (cutoff, 1, 2, did2, cid_new))
    conn.commit()
    conn.close()

    candidates = {c["ip"]: c for c in db.vendor_alert_candidates(cutoff)}
    assert "192.168.1.98" not in candidates, "established vendor's new client must not be flagged"
    assert candidates["192.168.1.99"]["kind"] == "new_vendor"
    assert candidates["192.168.1.99"]["vendor"] == "NewCo"


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


def test_count_queries_uses_id_fast_path_on_normalized_schema(ftl, monkeypatch):
    """#9: count_queries() must route the normalized (has_id_storage) schema
    through the query_storage fast path, not the `queries` view -- a plain
    COUNT(*) against the view pays a per-row correlated subquery to resolve
    the client id to a name, work a count never uses (profiled at ~10x slower
    against the real UAT snapshot). This pins the routing decision so a future
    refactor can't silently reintroduce the view path for this schema."""
    from app import db
    calls = []
    orig = db._count_queries_id

    def spy(*args):
        calls.append(args)
        return orig(*args)

    monkeypatch.setattr(db, "_count_queries_id", spy)
    db.count_queries(None, None, None, None, None)
    if ftl["schema"] == "idstore":
        assert calls, "expected count_queries to use the query_storage fast path"
    else:
        assert not calls


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


def test_tag_scoped_aggregates_match_ground_truth(ftl):
    """#31: db.py's `client` filter accepts a list of ips (a tag's members),
    not just a single one, across every function real endpoints call it with.
    Verified against a raw ground-truth IN-clause query, and cross-checked
    that the list result equals the sum of the two single-ip results (no
    double counting, no dropped rows) -- the two ips are deliberately
    disjoint clients, so their counts must add exactly."""
    from app import db
    conn = truth(ftl["path"])
    ips = ["192.168.1.10", "192.168.1.11"]
    if ftl["schema"] == "new":
        q = ("SELECT COUNT(*) n FROM queries q "
             "LEFT JOIN client c ON c.id=q.client_id WHERE c.ip IN (?,?)")
    else:
        q = "SELECT COUNT(*) n FROM queries q WHERE q.client IN (?,?)"
    expected = conn.execute(q, ips).fetchone()["n"]

    solo_total = sum(db.summary(ip, None, None)["total_queries"] for ip in ips)
    tagged = db.summary(ips, None, None)
    assert tagged["total_queries"] == expected == solo_total
    assert tagged["unique_clients"] == 2

    assert db.count_queries(ips, None, None, None, None) == expected

    # An empty list (a real tag with zero members) must match nothing, not
    # "no filter" -- the same distinction _build_where/_id_where already draw
    # between a single unknown ip (matches nothing) and None (no filter).
    assert db.summary([], None, None)["total_queries"] == 0
    assert db.count_queries([], None, None, None, None) == 0


def test_tag_scoped_top_domains_skips_the_single_client_rollup(ftl):
    """#31: top_domains()'s "All" range (since=None) is normally served from
    the rollup cache (a single client's own client_domain_rollup row, or the
    unfiltered domain_totals) -- neither of which has a per-tag breakdown.
    A list client must fall through to the direct/id-based scan instead of
    being (incorrectly) handed to the single-ip rollup reader, and the result
    must still be correct."""
    from app import db
    ips = ["192.168.1.10", "192.168.1.11"]
    solo_domains: dict[str, int] = {}
    for ip in ips:
        for row in db.top_domains(ip, None, 50):
            solo_domains[row["domain"]] = solo_domains.get(row["domain"], 0) + row["count"]

    tagged = {row["domain"]: row["count"] for row in db.top_domains(ips, None, 50)}
    assert tagged == solo_domains


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


def test_domain_queriers(ftl):
    """#46: distinct client ips that queried an exact domain within a window
    -- backs the correlated_new_device_domain alert rule, which needs to know
    WHO queried a just-first-seen domain. Two clients inside the window must
    both be returned; a third client's query OUTSIDE the window must not be;
    a domain never queried at all must return []."""
    import sqlite3
    import time
    from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id
    from app import db

    now = int(time.time())
    domain = "correlated-target.example.test"
    in_window_ips = [CLIENTS[0][0], CLIENTS[1][0]]
    outside_ip = CLIENTS[2][0]

    conn = sqlite3.connect(ftl["path"])
    if ftl["schema"] == "new":
        for ip in in_window_ips:
            cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == ip)
            conn.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
                (now, 1, 2, domain, cid),
            )
        cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == outside_ip)
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
            (now - 7200, 1, 2, domain, cid),
        )
    elif ftl["schema"] == "idstore":
        cur = conn.cursor()
        did = _idstore_domain_id(cur, domain)
        for ip in in_window_ips:
            name = next(n for cip, n in CLIENTS if cip == ip)
            cid = _idstore_client_id(cur, ip, name)
            conn.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (now, 1, 2, did, cid),
            )
        name = next(n for cip, n in CLIENTS if cip == outside_ip)
        cid = _idstore_client_id(cur, outside_ip, name)
        conn.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (now - 7200, 1, 2, did, cid),
        )
    else:
        stored_ts = float(now) if ftl["schema"] == "real" else now
        old_ts = float(now - 7200) if ftl["schema"] == "real" else now - 7200
        for ip in in_window_ips:
            conn.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (stored_ts, 1, 2, domain, ip),
            )
        conn.execute(
            "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (old_ts, 1, 2, domain, outside_ip),
        )
    conn.commit()
    conn.close()

    result = set(db.domain_queriers(domain, now - 60, now + 60))
    assert result == set(in_window_ips)
    assert db.domain_queriers("never-queried.example.test", now - 60, now + 60) == []
