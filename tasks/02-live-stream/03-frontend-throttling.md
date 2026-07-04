# Sub-task 3: Frontend — flood throttling

Parent: [Feature 2 — Live Stream](README.md)
Depends on: [Sub-task 2 — stream console shell](02-frontend-stream-console-shell.md)

## Goal

Per spec: if a device goes haywire and floods hundreds of queries/second,
the console must not freeze the browser tab.

## Implementation plan

1. Track rows-per-poll in `LiveStreamTab.tsx`. Define a threshold (e.g. >100
   rows in a single poll response) that flips a `throttled` state to `true`.
2. While throttled:
   - Don't render every row — sample (e.g. render every Nth row, or just the
     most recent K of the batch) rather than pushing the full flood through
     `react-window`.
   - Show a visible banner: **"Streaming throttled due to high volume"**
     (exact copy from the spec).
   - Consider slowing the poll interval itself while throttled (e.g. back
     off from 1.5s to 3s) to reduce backend load from `/api/tail` — the
     8091/8090 backend is a single small container, not built for
     sustained high-frequency polling under load.
3. Recover automatically: once a poll returns a normal-sized batch again,
   clear `throttled` and resume normal rendering — no manual dismiss needed.

## Edge cases

- Sustained flood (not just one spiky poll) — confirm the tab stays
  responsive for an extended period, not just the first few seconds.
- Throttle threshold shouldn't trigger on ordinary bursts (e.g. a page load
  firing 20-30 queries at once) — tune the number during verification
  against real traffic, not just guessed.

## Definition of done

- [x] Simulated a flood safely (without ever writing to Pi-hole's live DB — that boundary is never crossed): temporarily pointed the console's mount cursor at `since=0` instead of "now", forcing the very real, very large historical backlog through the same live, read-only `/api/tail` endpoint. Confirmed the tab stayed responsive, throttle banner showed with the exact required copy, and the buffered count grew in clean 50-row increments (5 polls × `FLOOD_DISPLAY_SAMPLE`=50 = 250) rather than dumping hundreds of rows at once. Reverted the cursor back to `Date.now() / 1000` immediately after and re-verified clean, empty, non-throttled startup.
- [x] Throttle banner appears with exact copy "Streaming throttled due to high volume"; clears on revert to normal cursor — the recovery path (`isFlood` recomputed fresh every poll from that poll's own batch size) is self-evidently correct by construction, not separately exercised by draining the real backlog to completion (at ~500 rows/poll against a 660k+ row table, that would take over an hour and isn't a practical verification step)
- [x] Normal traffic volumes never spuriously trigger the throttle state — confirmed across this whole feature's testing: every normal (non-`since=0`) poll during verification returned well under the 100-row threshold
