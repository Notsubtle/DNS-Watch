"""Cursor-based tail endpoint (`db.tail_queries` / `GET /api/tail`) — the
polling feed behind the Live Stream console."""

from __future__ import annotations

import time

from conftest import insert_queries_at_timestamp


def test_returns_rows_strictly_after_cursor_ascending(ftl):
    from app import db

    all_rows = db.tail_queries(0, 0, limit=10000)
    assert len(all_rows) > 0
    # Ascending order, by construction of tail_queries()'s ORDER BY.
    timestamps = [r["timestamp"] for r in all_rows]
    assert timestamps == sorted(timestamps)

    # Cursor at the very first row must exclude it and everything before it.
    first = all_rows[0]
    after = db.tail_queries(first["timestamp"], first["id"], limit=10000)
    assert first["id"] not in {r["id"] for r in after}
    assert len(after) == len(all_rows) - 1


def test_repeated_polling_never_skips_or_repeats_a_row(ftl):
    """Simulates a real polling loop: call, advance the cursor to the last
    row received, call again — across a run with a genuine same-timestamp
    burst, which is the actual case the compound cursor exists for."""
    from app import db

    burst_ts = time.time() - 1800  # 30 minutes ago, clear of build_ftl()'s spread
    burst_ids = insert_queries_at_timestamp(ftl["path"], ftl["schema"], burst_ts, n=5)

    since, since_id = 0, 0
    seen_ids: list[int] = []
    for _ in range(200):  # more than enough polls to drain a few hundred rows
        batch = db.tail_queries(since, since_id, limit=7)  # small limit forces many polls
        if not batch:
            break
        seen_ids.extend(r["id"] for r in batch)
        since, since_id = batch[-1]["timestamp"], batch[-1]["id"]

    # No duplicates across the whole polling run.
    assert len(seen_ids) == len(set(seen_ids))
    # Every burst row was actually seen exactly once, in `id` order (their
    # shared timestamp means only `id` can be breaking the tie correctly).
    seen_burst = [i for i in seen_ids if i in burst_ids]
    assert seen_burst == sorted(burst_ids)


def test_limit_is_respected(ftl):
    from app import db

    rows = db.tail_queries(0, 0, limit=3)
    assert len(rows) <= 3


def test_api_tail_endpoint(client):
    resp = client.get("/api/tail", params={"since": 0, "since_id": 0, "limit": 500})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    if body:
        assert "id" in body[0] and "timestamp" in body[0] and "domain" in body[0]


def test_api_tail_requires_since():
    from app.main import app
    from fastapi.testclient import TestClient

    # `since` has no default (see main.py) — a bare call must 422, not
    # silently dump the whole table.
    resp = TestClient(app).get("/api/tail")
    assert resp.status_code == 422
