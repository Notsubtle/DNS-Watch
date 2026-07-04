# Sub-task 1: Backend — heatmap aggregation + drill-down

Parent: [Feature 4 — Client Heatmap](README.md)

## Goal

An endpoint returning one client's queries bucketed into a 7×24
(weekday × hour) grid in the caller's local time, plus a way to fetch the
exact rows behind any one cell.

## Implementation plan

1. In `server/app/db.py`, add:
   ```python
   def client_heatmap(client_ip: str, tz_name: str, days: int = 7) -> dict
   ```
   - `zoneinfo.ZoneInfo(tz_name)` — catch `zoneinfo.ZoneInfoNotFoundError`
     and let it become a `400` in `main.py` (invalid/unknown tz string from
     a malformed client, not something to guess around).
   - Compute a single UTC offset for "now" in that zone (see README's
     accepted DST simplification), apply it uniformly to every row's
     timestamp before bucketing.
   - Pull raw `(timestamp,)` rows for the client over `[now - days*86400,
     now)` (reuse `_client_ip_col()` / `_build_where()` filtering, same as
     every other function in this module), then bucket in Python:
     `weekday = local_dt.weekday()` (Monday=0 — document this convention
     explicitly, it's an easy off-by-one for the frontend to get backwards),
     `hour = local_dt.hour`.
   - Return:
     ```python
     {
       "tz": tz_name, "days": days,
       "grid": [[count for hour in range(24)] for weekday in range(7)],
       "max": <highest single-cell count>,
     }
     ```

2. **Drill-down — same offset logic, not re-derived on the frontend.** Add:
   ```python
   def client_heatmap_cell(client_ip: str, tz_name: str, weekday: int, hour: int, days: int = 7) -> list[dict]
   ```
   Converts the given local `(weekday, hour)` back to a UTC `[since, until)`
   range using the *same* offset computation as `client_heatmap()` (factor
   the offset calculation into one shared helper so the two can never
   silently drift apart), then calls the existing `list_queries()` with
   those bounds. This keeps all timezone math in one place in the backend —
   the frontend never computes UTC bounds itself.

3. New routes in `server/app/main.py`:
   ```python
   @app.get("/api/client/{ip}/heatmap")
   def api_client_heatmap(ip: str, tz: str, days: int = Query(7, ge=1, le=30)):
       ...

   @app.get("/api/client/{ip}/heatmap/cell")
   def api_client_heatmap_cell(ip: str, tz: str, weekday: int, hour: int, days: int = 7):
       ...
   ```

## Edge cases

- Unknown/malformed `tz` string → `400`, not a 500 from an uncaught
  `ZoneInfoNotFoundError`.
- Client with sparse data (real-world case — most Cube1 devices won't have
  traffic in every one of the 168 cells) → zero-count cells are a normal,
  valid result, not an error.
- `weekday`/`hour` out of range on the drill-down endpoint → `400`.
- Must work across all three `ftl` schema variants.

## Tests

- [x] Known synthetic timestamps in a fixed tz bucket into the expected weekday/hour cells
- [x] Drill-down for a given cell returns exactly the rows that fed that cell's count (round-trip check: sum of drill-down row counts across all 168 cells == total client query count in the window)
- [x] Invalid `tz` → `400`
- [x] Covered across all three schema variants

## Definition of done

- [x] `client_heatmap()`, `client_heatmap_cell()`, and both routes added
- [x] Tests pass: `docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"` (26 new tests, 205/205 total)

## What actually happened

Implementation matches the plan, with one real design decision the plan
left implicit and one deprecation fix:

- **The drill-down endpoint walks every local calendar day in the window,
  not just the most recent occurrence of the requested weekday.** A literal
  reading of "converts the given local (weekday, hour) back to a UTC
  [since, until) range" (singular) works for the default `days=7` (a
  rolling 7-day window contains each weekday exactly once), but the same
  endpoint accepts `days` up to 30 (matching the heatmap endpoint's own
  `Query(7, ge=1, le=30)` bound), where a weekday can recur 4-5 times.
  `client_heatmap_cell()` walks the window one local calendar day at a
  time, converting each matching day's local hour range to UTC (clipped to
  the actual `[since, now)` bounds) and calling `list_queries()` once per
  occurrence, then merges and sorts the results — this is what makes the
  round-trip test (sum of all 168 cells' drill-down counts == the grid's
  total) hold for any `days` value, not just 7.
- **`datetime.utcfromtimestamp()` is deprecated** (Python 3.12 warns it's
  scheduled for removal). Used `datetime.fromtimestamp(ts, tz=timezone.utc)`
  throughout instead — same `.weekday()`/`.hour` values, no deprecation
  warnings in the test run (was 5,586 warnings before the fix, 0 after).
- No other deviations — the connection-scoped nothing-new-here database
  access (no schema/index changes), the shared `_local_offset_seconds()`
  helper (so the grid and drill-down endpoints can never silently drift
  apart on their offset math), and the `ZoneInfoNotFoundError`/`ValueError`
  → 400 mapping in `main.py` all worked as planned on the first pass.

## Post-review fix (2026-07-04) — malformed tz 500'd on the `/heatmap` route

A later full-code review found the "unknown/malformed tz → 400" edge case
wasn't fully covered. `zoneinfo.ZoneInfo` raises `ValueError` (NOT
`ZoneInfoNotFoundError`) for keys with a path-traversal / absolute-path
shape, e.g. `../../etc/passwd`. The `/api/client/{ip}/heatmap` route only
caught `ZoneInfoNotFoundError`, so such a tz produced a **500** (verified
live). The `/heatmap/cell` route didn't 500 — it catches `ValueError` for
its weekday/hour validation — but that meant it returned a 400 leaking the
raw internal message (`"ZoneInfo keys must refer to subdirectories of
TZPATH…"`) instead of a clean one.

Fixed at the source in `_local_offset_seconds()`: it now catches the
`ValueError` from `ZoneInfo(...)` and re-raises it as `ZoneInfoNotFoundError`,
so every caller only has to handle one "bad tz" exception type and the raw
message never leaks. Both routes now return a clean `400 {"detail": "Unknown
timezone"}` for any bad tz. Regression tests:
`test_malformed_tz_normalized_to_zoneinfo_not_found` (unit) and
`test_api_malformed_tz_returns_400_not_500` (both routes).
