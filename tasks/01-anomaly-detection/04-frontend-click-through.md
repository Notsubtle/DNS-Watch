# Sub-task 4: Frontend — click-through to filtered view

Parent: [Feature 1 — Silent Talker / Anomaly Detection](README.md)
Depends on: [Sub-task 3 — anomalies panel](03-frontend-anomalies-panel.md)

## Goal

Per the spec's user journey: clicking an anomaly filters the main query view
to that client, scoped to when the anomaly happened.

## Open design question — resolve before implementing

`Filters.range` in `web/src/api.ts` is currently a fixed preset string
(`"15m" | "1h" | "24h" | "7d"`), and `FilterBar` has no explicit
since/until inputs. The spec wants the view to jump to "the exact moment the
spike began," which doesn't cleanly map to a preset.

**Recommended v1 approach** (avoid gold-plating an app-wide filter-model
change for this one feature): pick the smallest preset range that fully
contains `[window_since, window_until]` from the anomaly (e.g. an anomaly
with a 3-hour window → `"24h"` preset, since there's no `"3h"` preset today).
Set `filters.client = anomaly.ip` and `filters.range` to that nearest preset.
This gets the user to the right client with the right general timeframe in
one click, which satisfies the journey's intent, without introducing
arbitrary since/until support into `FilterBar`/`Filters` as a side effect of
this feature.

If you'd rather do exact since/until, that's a larger change (touches
`Filters`, `FilterBar`, and every `api.ts` call that takes `Pick<Filters, ...>`)
— flag it back before starting if you want that instead of the approximation
above.

## Implementation plan

1. In `App.tsx`, wire `AnomaliesPanel`'s `onSelect` to call the existing
   `setFilters()` (already resets paging via its existing side effect) with
   `{ ...filters, client: anomaly.ip, range: nearestPreset(anomaly) }`.
2. Add the small `nearestPreset()` helper (colocated in `AnomaliesPanel.tsx`
   or `App.tsx` — whichever keeps `App.tsx`'s existing size in check).
3. No new modal needed — this reuses the existing dashboard filter state,
   consistent with how `ClientList`'s click-through already works (`onSelect`
   → `setClientDetail`), except here it drives the main filter bar instead of
   opening a modal, per the spec's journey ("dashboard automatically applies
   a filter to the main query view").

## Definition of done

- [x] Clicking an anomaly in the panel updates `FilterBar`'s client dropdown and range to match — confirmed via screenshot: clicking the `192.168.0.185` silent anomaly set the client dropdown to `192.168.0.185 (21912)` and range to `24h`
- [x] Query table, summary cards, and charts all reflect the filtered view immediately — confirmed via network log: `/api/queries?client=192.168.0.185&...&range=24h` and all other panel endpoints fired with the same filter after the click
- [x] Verified visually against the real UAT snapshot on both `localhost:5173` (dev) and `localhost:8092` (prod-like, rebuilt with these changes)
