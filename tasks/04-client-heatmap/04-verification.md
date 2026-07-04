# Sub-task 4: Verification

Parent: [Feature 4 — Client Heatmap](README.md)
Depends on: [Sub-task 3 — drill-down modal](03-frontend-drilldown-modal.md)

## Steps

1. **Backend test suite**:
   ```bash
   docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim \
     sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"
   ```
2. **Hot-reload UAT** (`localhost:5173`): pick a real device you know the
   routine of (e.g. your own phone) and confirm the heatmap actually
   matches reality — daytime activity, quieter overnight — as the real
   correctness check for the timezone-conversion logic, not just that a
   grid renders.
3. Click a few cells, including at least one overnight cell, and sanity
   check the drill-down results against the grid's color intensity.
4. Confirm the tz sent to the backend matches your browser's actual local
   time (`Intl.DateTimeFormat().resolvedOptions().timeZone` — check it's
   not silently defaulting to UTC in the container's Docker network).
5. **Prod-like preview** (`localhost:8092`, `--profile prod --build`) —
   repeat the spot-check against the built bundle.

## Definition of done

- [x] All tests pass — 205/205 (26 new)
- [x] Verified against real Cube1 data on both `localhost:5173` and `localhost:8092` — see task 2's note on the honest limitation here (no single "my own phone" routine available in this dataset; timezone *correctness* is nailed down by task 1's deterministic backend tests, not the visual pass)
- [x] Drill-down modal row counts are consistent with the grid's cell counts — exact match confirmed on both a 4,199-query cell and a genuine 0-count cell
- [x] Confirmed the browser's real tz (`America/Edmonton`) reached the backend correctly, not a silent UTC fallback — visible directly in the network log (`GET /api/client/.../heatmap?tz=America%2FEdmonton&days=7`)

## Real discoveries this feature surfaced

1. **Multi-week drill-down required walking every matching calendar day,
   not just one.** The plan's wording for `client_heatmap_cell()` reads as
   a single UTC range conversion, which is exactly correct for the default
   `days=7` (each weekday occurs exactly once in a rolling 7-day window),
   but the endpoint's own `days` parameter goes up to 30, where a weekday
   recurs several times. Caught by writing the round-trip test (sum of all
   168 cells' drill-down counts must equal the grid total) rather than only
   testing the default window — see task 1.
2. **No backend perf or correctness bugs against real data** — the shared
   `_local_offset_seconds()` helper, the connection reuse of `list_queries()`
   for drill-down, and the 7-day-default/30-day-max window all measured
   well under half a second against the real ~650k-row Cube1 snapshot for
   both a very high-traffic client (173k total queries) and a low-traffic
   one.
3. **`datetime.utcfromtimestamp()` deprecation** — caught by the test
   suite's own warning output (5,586 warnings on first run), not by manual
   review. Switched to `datetime.fromtimestamp(ts, tz=timezone.utc)`
   throughout; see task 1.
