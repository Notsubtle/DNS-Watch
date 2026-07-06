"""HTTP surface: response shapes, pagination, CSV."""

from __future__ import annotations

import csv
import io


def test_queries_envelope_and_total(client):
    r = client.get("/api/queries?range=all&limit=10").json()
    assert set(r) >= {"total", "limit", "offset", "rows"}
    assert r["total"] == 500
    assert len(r["rows"]) == 10
    assert "status" in r["rows"][0]


def test_queries_pagination_offset(client):
    p2 = client.get("/api/queries?range=all&limit=200&offset=200").json()
    assert p2["offset"] == 200
    assert len(p2["rows"]) == 200  # 500 total -> rows 201..400


def test_status_filter_endpoint(client):
    rb = client.get("/api/queries?range=all&status=blocked&limit=10").json()
    assert len(rb["rows"]) == 10
    assert all(x["status"] == "blocked" for x in rb["rows"])
    assert 0 < rb["total"] < 500


def test_summary_endpoint(client):
    s = client.get("/api/summary?range=all").json()
    assert s["total_queries"] == 500
    assert {"blocked", "blocked_pct", "unique_clients", "unique_domains"} <= set(s)


def test_analytics_endpoints(client):
    ts = client.get("/api/timeseries?range=all&buckets=20").json()
    assert sum(p["total"] for p in ts["series"]) == 500

    qt = client.get("/api/query-types?range=all").json()
    assert sum(x["count"] for x in qt) == 500

    ca = client.get("/api/client-activity?range=all").json()
    assert ca and all("sparkline" in c for c in ca)


def test_timeseries_bucket_validation(client):
    assert client.get("/api/timeseries?range=all&buckets=9999").status_code == 422


def test_client_detail_endpoint(client):
    d = client.get("/api/client/192.168.1.10?range=all").json()
    assert d["ip"] == "192.168.1.10"
    assert d["first_seen"] is not None and d["last_seen"] is not None
    # bundled sections present and internally consistent
    assert d["summary"]["total_queries"] == sum(x["count"] for x in d["query_types"])
    assert sum(p["total"] for p in d["timeseries"]["series"]) == d["summary"]["total_queries"]
    assert len(d["top_domains"]) > 0


def test_client_detail_vendor_fields(client, ftl):
    """Vendor enrichment (#4): present for schemas with a network table
    carrying hwaddr/macVendor ("real", "idstore"); gracefully absent
    (mac_known False, vendor None) for schemas that have none ("new", "old")."""
    d = client.get("/api/client/192.168.1.10?range=all").json()
    assert {"hwaddr", "mac_known", "vendor", "vendor_unknown_reason"} <= set(d)
    if ftl["schema"] in ("real", "idstore"):
        assert d["mac_known"] is True
        assert d["hwaddr"] and d["hwaddr"].count(":") == 5
        assert d["vendor"] == "TestVendor"
    else:
        assert d["mac_known"] is False
        assert d["hwaddr"] is None
        assert d["vendor"] is None

    clients = client.get("/api/clients").json()
    row = next(c for c in clients if c["ip"] == "192.168.1.10")
    assert row["mac_known"] == d["mac_known"]
    assert row["vendor"] == d["vendor"]


def test_csv_export(client):
    r = client.get("/api/queries.csv?range=all&limit=1000")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers.get("content-disposition", "")
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][0] == "timestamp" and "status" in rows[0]
    assert len(rows) == 501  # header + 500

    blocked = list(csv.reader(io.StringIO(
        client.get("/api/queries.csv?range=all&status=blocked&limit=1000").text)))
    assert {row[6] for row in blocked[1:]} == {"blocked"}
