# Sub-task 5: Verification

Parent: [Feature 1 — Silent Talker / Anomaly Detection](README.md)
Depends on: [Sub-task 4 — click-through](04-frontend-click-through.md)

## Goal

Confirm the whole feature works end-to-end against real data before calling
Feature 1 done — the same discipline that caught the two real Pi-hole-schema
bugs on 2026-07-04 (synthetic-only testing wasn't enough).

## Steps

1. **Full backend test suite** (all of Feature 1's tests + existing suite):
   ```bash
   docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim \
     sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"
   ```
2. **Refresh the UAT snapshot** so this session's data is current:
   ```bash
   ./uat/snapshot-pihole-db.sh
   ```
3. **Hot-reload UAT stack** (`localhost:5173`):
   - Confirm `/api/anomalies` returns real data (or a clean empty array —
     your actual Cube1 network may not have any genuinely silent/spiking
     devices right now, which is a valid outcome, not a bug).
   - If nothing's currently flagged, temporarily lower the thresholds
     locally (e.g. baseline > 1/hr instead of > 10/hr) just to visually
     confirm the panel renders a populated state and the click-through
     works — then revert the threshold change. Don't ship a lowered
     threshold.
4. **Prod-like preview** (`localhost:8092`, `--profile prod --build`) —
   confirm the built bundle also renders the widget correctly (catches
   anything that only worked under Vite's dev-server behavior).
5. Re-read the edge cases from the feature `README.md` and `01-backend-baseline-engine.md`
   one more time against real device names/volumes in the UAT snapshot —
   specifically the new-device exclusion and low-volume whitelist, since
   those are the two easiest to silently get wrong.

## Definition of done

- [x] All tests pass (138/138, including 24 new anomaly-specific tests)
- [x] Verified visually on both `localhost:5173` (dev) and `localhost:8092` (prod-like) — real anomalies present throughout (no need to lower thresholds artificially: `192.168.0.185` genuinely silent ~66-90h, `172.18.0.1`/`192.168.0.99` genuine spikes)
- [x] No thresholds left artificially lowered from the spec's values (10/hr, 3 consecutive hours, 3σ, 24h) — never needed to touch them, real data exercised both code paths
- [x] Feature README's fixed-thresholds table still matches what's actually in the code

## Unplanned but load-bearing: performance

Not anticipated in the original plan — real production data surfaced two
correctness/perf issues no synthetic fixture could have caught:

1. **A real bug**: both `hourly_client_counts()`-style queries and
   `_client_first_seen()` referenced `c.ip`/needed the client-table join on
   the newer schema but didn't include it — 500'd immediately on the "new"
   schema variant. Fixed by reusing `_client_join_sql()` like every other
   function in `db.py`.
2. **A real perf bug**: the original per-client-loop design (2 queries ×
   ~19 real clients) measured **6-7 seconds** against the actual Cube1
   snapshot — because Pi-hole's `queries` table has no index on the client
   column (and never can, this module is read-only by design). Rewrote
   `detect_anomalies()` around 2 batched queries total (not per-client),
   getting this to ~1.5s, then decoupled the frontend poll from the 5s
   dashboard refresh onto its own 60s interval (matching data granularity),
   which is what actually made the remaining 1.5s a non-issue.
3. **A UAT harness bug**, found while chasing what looked like a detection
   bug: `docker-compose.uat.yml` bind-mounted the snapshot as a single file,
   which pins Docker to the original inode — `snapshot-pihole-db.sh`'s
   `VACUUM INTO` replaces the file rather than editing it in place, so a
   running container silently kept serving the first snapshot forever.
   Fixed by mounting the containing directory instead. This affects every
   future feature's verification against fresh data, not just this one.
