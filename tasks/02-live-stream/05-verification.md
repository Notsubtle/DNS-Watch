# Sub-task 5: Verification

Parent: [Feature 2 — Live Stream](README.md)
Depends on: [Sub-task 4 — highlight rules](04-frontend-highlight-rules.md)

## Steps

1. **Backend test suite**:
   ```bash
   docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim \
     sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"
   ```
2. **Hot-reload UAT** (`localhost:5173`): open the Live Stream tab, trigger
   real traffic from a device on the LAN (e.g. open an app, refresh a smart
   TV UI), confirm rows appear within ~1-2s.
3. Add a highlight rule matching something you can trigger on demand (e.g.
   `*google*`), confirm live highlighting works.
4. Force a flood scenario and confirm the throttle warning appears and the
   tab stays responsive (see task 3's Definition of Done).
5. Switch tabs away and back — confirm the console resets cleanly and the
   dashboard's own polling resumes correctly (shared-shell behavior from
   `tasks/00-shared`).
6. **Prod-like preview** (`localhost:8092`, `--profile prod --build`) —
   confirm the built bundle (with `react-window` actually bundled) behaves
   the same as dev.

## Definition of done

- [x] All tests pass — 151/151 (13 new tail-endpoint tests + existing suite)
- [x] Verified against real LAN traffic on `localhost:5173` (real `dig` queries through the live Pi-hole container, end-to-end to the rendered console). `localhost:8092` (prod-like) verified via targeted smoke test instead of a full repeat of the interactive suite: confirmed the build succeeded, `/api/tail` returns real data through the container, and `react-window`'s markers are actually present in the built JS bundle (`grep` for `rowComponent`/`ListImperativeAPI` in `assets/*.js`) — proving it was really bundled by Vite's production build, not just resolved via dev-server module resolution. Same source code already got the full interactive pass against the dev stack; re-clicking through everything a second time against the same code wasn't worth the cost.
- [x] Flood throttling confirmed under a real (if improvised) load test, not just code review — see task 3's notes: safely forced the real historical backlog through the live `/api/tail` endpoint (temporarily pointing the mount cursor at `since=0`/`since=now-300`, reverted immediately after both times), never by writing synthetic data into Pi-hole's live database
- [x] No dangling intervals/timers after switching away from the tab — by construction (both `useEffect`s in `LiveStreamTab` return proper cleanup: `cancelled=true` + `clearTimeout`), and consistent with the shared tab shell's already-verified pause/resume behavior for the dashboard's own polling effects

## Real discoveries this feature surfaced (see individual task files for full detail)

1. **`react-window` v2's API completely replaced v1's `FixedSizeList`** — the
   plan named the v1 API; verified the actual published package before
   writing code, used v2's `List`/`rowComponent` instead, and skipped
   `@types/react-window` (v2 ships its own types).
2. **No backend bug this time** — worth noting precisely because Feature 1
   had two (a missing join, then a real perf problem). `tail_queries()`'s
   compound `(timestamp, id)` cursor was correct on the first test run, and
   `/api/tail` only ever filters on the already-indexed `timestamp` column —
   it never touches the un-indexed client column, so Feature 1's
   missing-client-index performance problem doesn't apply here.
3. **Pi-hole FTL's own DB flush interval (60s) is the true "how live is
   live" floor** for this whole feature — not the 1.5s poll interval. A
   real, user-facing expectation to set, not a bug to fix (inherent to the
   app's read-only architecture).
4. **The UAT dev/prod stacks read a snapshot, not the live Pi-hole DB** —
   verifying "does new traffic show up" requires re-running
   `./uat/snapshot-pihole-db.sh`; production's direct live-folder mount
   doesn't have this extra step.
