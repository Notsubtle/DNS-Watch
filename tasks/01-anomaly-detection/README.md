# Feature 1 — Silent Talker / Anomaly Detection

Automatically flag clients whose query volume deviates from their own
historical norm — a device gone silent (likely dead/offline) or a device
spiking (likely misbehaving/compromised) — surfaced as a widget on the main
dashboard. No push notifications, no remediation: informational only, v1.

No dependency on the shared tab-navigation shell — this widget lives directly
on the existing dashboard view, not a new tab.

## Sub-tasks (in order)

1. [Backend: baseline & detection engine](01-backend-baseline-engine.md)
2. [Backend: API endpoint & tests](02-backend-api-and-tests.md)
3. [Frontend: anomalies panel](03-frontend-anomalies-panel.md)
4. [Frontend: click-through to filtered view](04-frontend-click-through.md)
5. [Verification](05-verification.md)

## Key design decision (read before implementing #1)

The 7-day baseline **must exclude the detection window itself**, or the
feature can't reliably trigger:
- A silence would drag its own baseline average down toward zero, making the
  device look "always quiet" instead of anomalous.
- A live spike would elevate the average that same spike is being compared
  against.

So: baseline = trailing 7 days **minus** the last 3 hours; detection window =
the last 3 hours (silent) / last 1 hour (spike). See task 1 for specifics.

## Fixed thresholds (from spec — not user-configurable in v1)

| Rule | Condition |
|---|---|
| Silent | baseline avg > 10 queries/hr AND 0 queries in each of the last 3 consecutive hours |
| Spike | current hour's count > baseline avg + 3 × baseline stddev |
| New-device exclusion | client's global first-seen < 24h ago → excluded from both checks |

## Performance (discovered during implementation, not in the original plan)

`detect_anomalies()` must run as **2 batched queries total**, never a
per-client loop. Pi-hole's `queries` table has no index on the client
column (and this module can never add one — it's read-only by design), so a
per-client loop repeats the same large timestamp-range scan once per
client: measured **6-7 seconds** against the real ~650k-row Cube1 snapshot
for ~19 clients. The frontend also polls this endpoint on its **own 60s
interval**, independent of the dashboard's 5s refresh — anomaly detection is
hourly-granularity data, so nothing changes between one 5s tick and the
next anyway. See task 2 and task 5 for the full story.
