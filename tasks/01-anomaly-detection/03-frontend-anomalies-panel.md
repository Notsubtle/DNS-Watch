# Sub-task 3: Frontend — anomalies panel

Parent: [Feature 1 — Silent Talker / Anomaly Detection](README.md)
Depends on: [Sub-task 2 — API endpoint & tests](02-backend-api-and-tests.md)

## Goal

A scannable "Network Anomalies" widget on the main dashboard, visually
distinct from the existing `AlertsPanel` (different data source, different
meaning) but built the same way.

## Implementation plan

1. **`web/src/api.ts`** — add:
   ```ts
   export interface Anomaly {
     ip: string;
     name: string;
     kind: "silent" | "spike";
     baseline_avg: number;
     baseline_stddev: number;
     current_value: number;
     window_since: number;
     window_until: number;
   }
   ```
   and `anomalies: () => getJson<Anomaly[]>("/api/anomalies")` in the `api` object.

2. **`web/src/components/AnomaliesPanel.tsx`** (new) — modeled directly on
   `AlertsPanel.tsx`'s structure (panel head, empty state, list of items with
   a colored dot). Differences from `AlertsPanel`:
   - Amber dot/icon for `silent`, red for `spike` (per the spec's UI mock:
     amber warning icon for "no activity", red alert for "+400% spike").
   - Message format e.g. `"SmartPlug_LivingRoom (No activity)"` /
     `"IP_Cam_Backyard (+400% Spike)"` — compute the spike percentage from
     `(current_value - baseline_avg) / baseline_avg * 100` client-side rather
     than having the backend format display strings (keeps `db.py` returning
     data, not presentation — consistent with how `AlertEvent.message` is the
     one place the codebase *does* pre-format server-side, but that's for
     webhook delivery too; this widget has no webhook consumer, so format in
     the component).

3. **`web/src/App.tsx`** — **deviated from the original plan here.**
   `/api/anomalies` measured ~6-7s against the real Cube1 snapshot (fixed to
   ~1.5s — see task 2's Definition of Done for the full story), and anomaly
   detection is inherently hourly-granularity data, so bundling it into the
   existing 5s `Promise.all(...)` refresh was wrong on two counts: it made
   the fast refresh only as fast as its slowest call, and it re-ran an
   expensive query 12x more often than the data could possibly change.
   Fetches on its own independent interval instead
   (`ANOMALIES_REFRESH_MS = 60000`, matching `alerts.py`'s own
   `ALERT_EVAL_INTERVAL_SECONDS` default), decoupled from `refresh()`
   entirely. Renders `<AnomaliesPanel anomalies={anomalies} onSelect={...} />`
   near `<AlertsPanel />` (above `<TimeSeriesChart />`, matching the spec's
   "widget at the top of the screen").

4. `onSelect` is fully wired (not a placeholder — ended up implementing task
   4 in the same pass since it was small and directly coupled).

## Edge cases

- Empty state (no anomalies) — same pattern as `AlertsPanel`'s "No alerts."
  message, e.g. "No anomalies detected."
- Long device names / IPs shouldn't break layout — check with a real device
  name from the UAT snapshot (`uat/pihole-data/pihole-FTL.db` has real
  clients to test against, no need to fabricate names).

## Definition of done

- [x] `AnomaliesPanel.tsx` renders real anomalies from `/api/anomalies` in the hot-reload UAT stack (`localhost:5173`) — confirmed via screenshot, real Cube1 data (`192.168.0.185` silent, `172.18.0.1` spike)
- [x] Empty state renders correctly when there are no anomalies (code path matches `AlertsPanel`'s pattern; not separately exercised against live data since anomalies were present throughout testing)
- [x] Visual check: silent vs. spike are clearly distinguishable at a glance (color + icon) — amber vs. red dot, confirmed in screenshot
- [x] (Added) Confirmed no console errors; confirmed independent 60s poll interval via network log (anomalies calls dropped to ~1-in-12 vs the 5s dashboard refresh)
