# Sub-task 2: Frontend — heatmap grid

Parent: [Feature 4 — Client Heatmap](README.md)
Depends on: [Shared tab shell](../00-shared/01-tab-navigation-shell.md), [Sub-task 1 — heatmap aggregation](01-backend-heatmap-aggregation.md)

## Goal

The "Client Heatmaps" tab: pick a client, see a 7×24 grid colored by
activity, scaled to that client's own busiest hour.

## Implementation plan

1. **`web/src/api.ts`** — add:
   ```ts
   export interface HeatmapResult { tz: string; days: number; grid: number[][]; max: number }
   clientHeatmap: (ip: string, days = 7) =>
     getJson<HeatmapResult>(`/api/client/${encodeURIComponent(ip)}/heatmap${qs({
       tz: Intl.DateTimeFormat().resolvedOptions().timeZone, days,
     })}`),
   ```

2. **`web/src/components/ClientHeatmapTab.tsx`** (new):
   - Client dropdown — reuse the `clients` list already fetched in `App.tsx`
     (pass down as a prop, same as `FilterBar` already receives `clients`),
     don't re-fetch independently.
   - On client selection, fetch the heatmap and render a CSS grid: 7 rows
     (label Mon–Sun — remember the backend's Monday=0 convention from task
     1), 24 columns (label 00–23 or just every few hours to avoid clutter).
   - **Color scaling normalized to that client's own `max`** — same
     "normalize to own max" principle `Sparkline.tsx` already uses elsewhere
     in this codebase, so a low-traffic client's pattern is still legible
     instead of looking uniformly dark next to a high-traffic one.
   - Hover tooltip showing the exact count for a cell.

## Edge cases

- Client with all-zero cells (brand new device, or one that's been fully
  offline for the window) — grid should render as uniformly "off," not
  crash on a `max` of 0 (guard the color-scale division).
- Long client names in the dropdown — reuse whatever truncation/`title`
  pattern the existing `ClientList.tsx` already uses.

## Definition of done

- [x] Select a real client from the UAT snapshot, see a populated grid
- [x] Visually confirm daytime cells read as more active than overnight cells for a normal device (e.g. a phone), as a sanity check that bucketing/timezone conversion is actually correct — not just that it renders
- [x] Color scale's brightest cell really is that client's single highest-count hour

## What actually happened

Implementation matches the plan closely. One honest caveat on the visual
sanity check:

- **Real Cube1 devices don't show a textbook "phone asleep at night"
  pattern** — this is a home network with routers/IoT/media devices, not a
  single person's phone whose routine I could personally verify. Sampled
  several real clients' hourly totals (summed across all 7 weekdays) via
  the live API: `192.168.1.67` shows the clearest day/night-style swing
  (a 06:00–10:00 morning peak around 7,000–8,000 queries/hour, dropping to
  ~500–900/hour in the early-to-mid afternoon), which is a reasonable
  stand-in for "the timezone math produces a believable activity rhythm,"
  but it isn't a clean sleep-schedule shape. The rigorous, unambiguous
  check for timezone *correctness* is task 1's backend test: insert a query
  at a known real timestamp, confirm it lands in the exact expected
  weekday/hour cell for a given tz, and confirm a different tz's multi-hour
  offset actually shifts that cell relative to UTC. The visual grid check
  here is a real-world plausibility pass on top of that, not a replacement
  for it.
- Color scale, dropdown reuse, and the `max`-normalized intensity (verified
  against both a very high-traffic client, where the grid's brightest cell
  title matched the reported `max` exactly, and a low-traffic client, where
  the grid still showed legible variation instead of looking uniformly
  faint) all worked as planned.
