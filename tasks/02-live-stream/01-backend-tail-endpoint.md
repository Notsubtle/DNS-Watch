# Sub-task 1: Backend — cursor-based tail endpoint

Parent: [Feature 2 — Live Stream](README.md)

## Goal

A polling-friendly "give me everything new since X" endpoint, distinct from
the existing paged/backwards `/api/queries`.

## Implementation plan

1. In `server/app/db.py`, add:
   ```python
   def tail_queries(since: float, since_id: int | None, limit: int = 500) -> list[dict]
   ```
   - `ORDER BY q.timestamp ASC, q.id ASC LIMIT ?`
   - Reuse `_client_join_sql()` / `_status_case()` exactly like `list_queries()`
     does — same row shape, so the frontend can share rendering code between
     the stream console and the existing `QueryTable`.

2. **Cursor correctness — use a compound cursor, not just a timestamp.**
   Real Pi-hole timestamps are floats (the exact bug fixed in `timeseries()`
   on 2026-07-04 — don't reintroduce a float-comparison assumption here).
   Two distinct rows can share the same float timestamp. Use:
   ```sql
   WHERE (q.timestamp > ?) OR (q.timestamp = ? AND q.id > ?)
   ```
   with `(since, since, since_id)` as params, so no row is ever skipped or
   double-delivered across polls. `q.id` already exists as the FTL table's
   primary key (see the real schema notes in `conftest.py`'s `build_ftl()`
   and the real-schema fixture).

3. New route in `server/app/main.py`:
   ```python
   @app.get("/api/tail")
   def api_tail(since: float, since_id: int = 0, limit: int = Query(500, le=2000)):
       return db.tail_queries(since, since_id, limit)
   ```
   No default for `since` — the frontend must pass "now" on first mount (see
   task 2) so a first call doesn't dump the client's entire history into the
   console.

## Edge cases

- First call ever (no prior cursor) → frontend passes current server/browser
  time; don't special-case this on the backend, it's just a normal `since`.
- Two rows with identical `(timestamp, id)` can't happen (`id` is the PK) —
  the compound cursor is airtight, no dedup logic needed downstream.
- Must work across all three `ftl` fixture schema variants — reuse the
  existing join helpers rather than writing new client-resolution SQL.

## Tests

- [x] `tail_queries()` returns rows strictly after a given cursor, ascending order
- [x] Simulating repeated polling (call with the last row's cursor each time) never re-returns or skips a row, across a synthetic batch of same-timestamp rows — used a new `insert_queries_at_timestamp()` conftest helper to force a genuine tie
- [x] `GET /api/tail` end-to-end via `TestClient`
- [x] All three schema variants covered by the parametrized `ftl` fixture
- [x] (Added) `since` has no default — a bare `GET /api/tail` 422s rather than silently dumping the whole table

13 new tests in `server/tests/test_tail.py`.

## Definition of done

- [x] `tail_queries()` + `/api/tail` added
- [x] Tests pass: 151/151 (13 new + existing suite), `docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"`
- [x] Verified against the real Cube1 snapshot: fast (3-100ms — this query only filters on the indexed `timestamp` column, unlike Feature 1's per-client queries, so none of that feature's perf issue applies here), correct real rows returned
