"""Client heatmap aggregation (`db.client_heatmap` / `db.client_heatmap_cell`)
and their routes — a 7x24 (weekday x hour) activity grid in the caller's own
local time, plus drill-down to the exact rows behind any one cell."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pytest

import sqlite3

from conftest import CLIENTS, _idstore_client_id, _idstore_domain_id, insert_queries_at_timestamp


def _insert_for_ip(ftl, ip: str, name: str, ts: float, n: int) -> None:
    """Same shape as insert_queries_at_timestamp, but for an ARBITRARY ip --
    that helper is hardcoded to CLIENTS[0], which can't exercise a
    multi-client tag scope."""
    conn = sqlite3.connect(ftl["path"])
    c = conn.cursor()
    for i in range(n):
        domain = f"tagburst-{ip}-{i}.example.com"
        if ftl["schema"] == "idstore":
            cid = _idstore_client_id(c, ip, name)
            did = _idstore_domain_id(c, domain)
            c.execute(
                "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (ts, 1, 2, did, cid),
            )
        elif ftl["schema"] == "new":
            cid = next(i for i, (cip, _) in enumerate(CLIENTS, 1) if cip == ip)
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
                (ts, 1, 2, domain, cid),
            )
        else:  # "old" / "real"
            stored_ts = float(ts) if ftl["schema"] == "real" else int(ts)
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (stored_ts, 1, 2, domain, ip),
            )
    conn.commit()
    conn.close()


def test_known_timestamp_buckets_into_expected_weekday_and_hour(ftl):
    from app import db

    ip = CLIENTS[0][0]
    ts = time.time() - 5 * 3600  # clear of build_ftl()'s spread (last 1h only)
    insert_queries_at_timestamp(ftl["path"], ftl["schema"], ts, n=3)

    expected = datetime.fromtimestamp(ts, tz=timezone.utc)
    result = db.client_heatmap(ip, "UTC", days=7)

    assert result["tz"] == "UTC"
    assert len(result["grid"]) == 7
    assert all(len(row) == 24 for row in result["grid"])
    assert result["grid"][expected.weekday()][expected.hour] == 3
    assert result["max"] >= 3


def test_offset_actually_shifts_bucket_vs_utc(ftl):
    from app import db

    ip = CLIENTS[0][0]
    ts = time.time() - 5 * 3600
    insert_queries_at_timestamp(ftl["path"], ftl["schema"], ts, n=1)

    offset = datetime.now(ZoneInfo("America/Edmonton")).utcoffset().total_seconds()
    utc_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    local_dt = datetime.fromtimestamp(ts + offset, tz=timezone.utc)

    result = db.client_heatmap(ip, "America/Edmonton", days=7)
    assert result["grid"][local_dt.weekday()][local_dt.hour] >= 1
    # Edmonton's multi-hour offset must actually shift the bucket relative to
    # a UTC-bucketed grid — this is the real correctness check for the
    # timezone conversion, not just that the endpoint runs.
    assert (local_dt.weekday(), local_dt.hour) != (utc_dt.weekday(), utc_dt.hour)


def test_invalid_tz_raises_zoneinfo_not_found(ftl):
    from app import db

    with pytest.raises(ZoneInfoNotFoundError):
        db.client_heatmap(CLIENTS[0][0], "Not/AZone", days=7)


def test_malformed_tz_normalized_to_zoneinfo_not_found(ftl):
    """A path-traversal-shaped tz key makes raw ZoneInfo raise ValueError, not
    ZoneInfoNotFoundError — which would slip past the routes' handler and 500.
    _local_offset_seconds must normalize it to the not-found type."""
    from app import db

    with pytest.raises(ZoneInfoNotFoundError):
        db.client_heatmap(CLIENTS[0][0], "../../etc/passwd", days=7)


def test_drilldown_rowcounts_match_and_sum_to_heatmap_total(ftl):
    """Round-trip: every cell's drill-down row count equals that cell's grid
    count, and the sum across all 168 cells equals the client's total."""
    from app import db

    ip = CLIENTS[0][0]
    heatmap = db.client_heatmap(ip, "UTC", days=7)
    total_from_grid = sum(c for row in heatmap["grid"] for c in row)

    total_from_cells = 0
    for weekday in range(7):
        for hour in range(24):
            cell_rows = db.client_heatmap_cell(ip, "UTC", weekday, hour, days=7)
            assert len(cell_rows) == heatmap["grid"][weekday][hour]
            total_from_cells += len(cell_rows)

    assert total_from_cells == total_from_grid
    assert total_from_grid > 0


def test_drilldown_invalid_weekday_or_hour_raises_value_error(ftl):
    from app import db

    ip = CLIENTS[0][0]
    with pytest.raises(ValueError):
        db.client_heatmap_cell(ip, "UTC", weekday=7, hour=0)
    with pytest.raises(ValueError):
        db.client_heatmap_cell(ip, "UTC", weekday=0, hour=24)


def test_tag_scoped_heatmap_sums_across_members(ftl):
    """#7: a tag's heatmap must equal the SUM of its members' individual
    heatmaps, cell by cell -- proves list-based client_heatmap() isn't just
    scoping to one arbitrary member."""
    from app import db

    ip_a, name_a = CLIENTS[0]
    ip_b, name_b = CLIENTS[1]
    ts = time.time() - 5 * 3600
    _insert_for_ip(ftl, ip_a, name_a, ts, n=2)
    _insert_for_ip(ftl, ip_b, name_b, ts, n=3)

    combined = db.client_heatmap([ip_a, ip_b], "UTC", days=7)
    a = db.client_heatmap(ip_a, "UTC", days=7)
    b = db.client_heatmap(ip_b, "UTC", days=7)

    for weekday in range(7):
        for hour in range(24):
            assert combined["grid"][weekday][hour] == a["grid"][weekday][hour] + b["grid"][weekday][hour]


def test_tag_heatmap_cell_drilldown_is_multi_client_aware(ftl):
    from app import db

    ip_a, name_a = CLIENTS[0]
    ip_b, name_b = CLIENTS[1]
    ts = time.time() - 5 * 3600
    _insert_for_ip(ftl, ip_a, name_a, ts, n=2)
    _insert_for_ip(ftl, ip_b, name_b, ts, n=3)

    expected = datetime.fromtimestamp(ts, tz=timezone.utc)
    rows = db.client_heatmap_cell([ip_a, ip_b], "UTC", expected.weekday(), expected.hour, days=7)
    seen_ips = {r["client_ip"] for r in rows}
    assert {ip_a, ip_b} <= seen_ips
    assert len(rows) == 5


def test_api_tag_heatmap_endpoint(client, ftl):
    from app import tags

    ip_a, ip_b = CLIENTS[0][0], CLIENTS[1][0]
    tag = tags.create_tag("iot")
    tags.add_member(tag["id"], ip_a)
    tags.add_member(tag["id"], ip_b)

    resp = client.get("/api/tags/iot/heatmap", params={"tz": "UTC"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["grid"]) == 7 and all(len(row) == 24 for row in body["grid"])


def test_api_tag_heatmap_unknown_tag_404s(client, ftl):
    resp = client.get("/api/tags/nope/heatmap", params={"tz": "UTC"})
    assert resp.status_code == 404


def test_api_tag_heatmap_cell_endpoint(client, ftl):
    from app import tags

    tag = tags.create_tag("iot2")
    tags.add_member(tag["id"], CLIENTS[0][0])

    resp = client.get("/api/tags/iot2/heatmap/cell", params={"tz": "UTC", "weekday": 0, "hour": 0})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_heatmap_endpoint_returns_full_shape(client):
    resp = client.get(f"/api/client/{CLIENTS[0][0]}/heatmap", params={"tz": "UTC"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["tz"] == "UTC"
    assert body["days"] == 7
    assert len(body["grid"]) == 7
    assert all(len(row) == 24 for row in body["grid"])


def test_api_heatmap_cell_endpoint(client):
    resp = client.get(
        f"/api/client/{CLIENTS[0][0]}/heatmap/cell",
        params={"tz": "UTC", "weekday": 0, "hour": 0},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_invalid_tz_returns_400(client):
    resp = client.get(f"/api/client/{CLIENTS[0][0]}/heatmap", params={"tz": "Not/AZone"})
    assert resp.status_code == 400


def test_api_malformed_tz_returns_400_not_500(client):
    """Both heatmap routes must turn a path-traversal-shaped tz into a clean
    400 with a generic message, never a 500 or a leaked internal ZoneInfo
    error string."""
    for path in ("heatmap", "heatmap/cell"):
        params = {"tz": "../../etc/passwd"}
        if path.endswith("cell"):
            params.update(weekday=0, hour=0)
        resp = client.get(f"/api/client/{CLIENTS[0][0]}/{path}", params=params)
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Unknown timezone"


def test_api_invalid_weekday_returns_400(client):
    resp = client.get(
        f"/api/client/{CLIENTS[0][0]}/heatmap/cell",
        params={"tz": "UTC", "weekday": 7, "hour": 0},
    )
    assert resp.status_code == 400


def test_api_invalid_hour_returns_400(client):
    resp = client.get(
        f"/api/client/{CLIENTS[0][0]}/heatmap/cell",
        params={"tz": "UTC", "weekday": 0, "hour": 24},
    )
    assert resp.status_code == 400
