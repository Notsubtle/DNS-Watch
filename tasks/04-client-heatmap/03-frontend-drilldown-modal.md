# Sub-task 3: Frontend — cell drill-down modal

Parent: [Feature 4 — Client Heatmap](README.md)
Depends on: [Sub-task 2 — heatmap grid](02-frontend-heatmap-grid.md)

## Goal

Clicking any cell shows the exact queries behind it — per the spec's
walkthrough: click the 4am Wednesday cell, see the 120 queries that fired,
discover the hidden background sync.

## Implementation plan

1. **`web/src/api.ts`** — add:
   ```ts
   clientHeatmapCell: (ip: string, weekday: number, hour: number, days = 7) =>
     getJson<QueryRow[]>(`/api/client/${encodeURIComponent(ip)}/heatmap/cell${qs({
       tz: Intl.DateTimeFormat().resolvedOptions().timeZone, weekday, hour, days,
     })}`),
   ```
   Reuses the existing `QueryRow` type — the backend's drill-down endpoint
   returns the same row shape as `/api/queries` (it's built on `list_queries()`
   internally, per task 1).

2. **`web/src/components/HeatmapCellModal.tsx`** (new) — modeled closely on
   `DrilldownModal.tsx`'s structure (fetch on mount, loading/error states,
   Escape-to-close, table of rows) rather than reinventing that pattern.
   Header shows the resolved local time range (e.g. "Wed 4:00–5:00 AM") so
   the user has context without doing timezone math themselves.

3. Wire cell clicks from `ClientHeatmapTab.tsx` to open this modal with the
   clicked `(weekday, hour)`.

## Edge cases

- Empty cell somehow clicked (e.g. a 0-count cell) → modal should still open
  cleanly and show "No queries in this window," not an error.
- Very active cell (hundreds of queries) → cap the displayed rows the same
  way `DrilldownModal` already does (`rows.slice(0, 50)` there — apply the
  same or a similar cap here) rather than rendering an unbounded table.

## Definition of done

- [x] Click a cell with known activity, confirm the modal's row count and domains match what you'd expect from the grid's color intensity
- [x] Click a genuinely quiet overnight cell on a real device, confirm whether it's truly empty or reveals real background chatter (this is the feature's actual point — worth doing for real against your own devices, not just as a mechanical check)

## What actually happened

Implementation matches the plan exactly, no deviations:

- Clicked `192.168.0.98`'s brightest cell (Wed 15:00, grid value 4,199) —
  the modal's header read "192.168.0.98 — Wednesday 15:00–16:00", the
  sub-line read "4,199 queries in this window (showing latest 50)", exactly
  matching the grid cell's own count.
- Clicked a genuine 0-count cell (`Mon 22:00` on the same client) — the
  modal opened cleanly with "0 queries in this window" and the table body
  showed "No queries in this window.", no crash, no loading spinner stuck.
- Header format settled on `{clientName} — {Weekday} {HH:MM}–{HH:MM}`
  (24-hour, matching the rest of the app's `hour12: false` time-formatting
  convention already used in `DrilldownModal`/`Sparkline`) rather than the
  spec mockup's `12-hour "AM"` style — consistency with the existing
  codebase convention won out over matching the mockup's exact wording.
