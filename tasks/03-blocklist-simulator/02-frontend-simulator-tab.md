# Sub-task 2: Frontend — simulator tab

Parent: [Feature 3 — Blocklist Simulator](README.md)
Depends on: [Shared tab shell](../00-shared/01-tab-navigation-shell.md), [Sub-task 1 — simulate endpoint](01-backend-simulate-endpoint.md)

## Goal

The "Blocklist Simulator" tab: paste a pattern, get an impact summary and a
domain breakdown, with a clean error state for bad regex.

## Implementation plan

1. **`web/src/api.ts`** — add:
   ```ts
   export interface SimulationClientImpact {
     ip: string;
     name: string;
     matched_count: number;
     total_count: number;
     pct_of_client_traffic: number;
   }
   export interface SimulationResult {
     pattern: string;
     since: number;
     total_matches: number;
     unique_domains: number;
     top_domains: { domain: string; count: number }[];
     clients: SimulationClientImpact[];
   }
   simulateBlocklist: (pattern: string) =>
     sendJson<SimulationResult>("/api/simulate-blocklist", "POST", { pattern, range: "7d" }),
   ```

2. **`web/src/components/SimulatorTab.tsx`** (new):
   - Textarea for the pattern + "Simulate" button (avoid simulating on every
     keystroke — this hits the real DB, unlike the debounced domain search
     already in `FilterBar`).
   - Loading state while the request is in flight.
   - Summary line matching the spec's tone: *"This rule would have blocked
     {total_matches} queries over the last 7 days. Impact: {clients.length}
     clients affected."* — plus a per-client warning line for any client
     whose `pct_of_client_traffic` is notably high (e.g. > 30%), styled like
     the spec's SmartFridge example.
   - "Deep dive" section: table of `top_domains` (reuse the existing
     `top-list`/table CSS classes, same pattern as `TopList.tsx`).

3. **Error handling** — a `400` from `sendJson` throws with the response
   status in the message (existing `sendJson` behavior); catch it
   specifically and render the exact copy from the spec: **"Invalid Regular
   Expression syntax"** in the existing `error-banner` class, distinct from a
   generic network-failure message.

## Edge cases

- Pattern with special regex characters that aren't actually invalid (e.g.
  `.` or `+`) should simulate normally — only truly malformed patterns (e.g.
  unbalanced groups) should hit the error path. Verify by testing a few
  intentionally-invalid patterns, not just the happy path.
- Very broad patterns (matching thousands of domains) — confirm the UI
  doesn't choke rendering a large `top_domains` table; consider a fixed
  display cap (e.g. top 50) even though the backend returns more.

## Definition of done

- [x] Paste `^(.+[-.])?telemetry[.-]`-style pattern against the real UAT snapshot, get a real, sane-looking impact summary
- [x] Intentionally malformed regex shows the exact "Invalid Regular Expression syntax" message, not a crash or generic error
- [x] Domain breakdown table renders and is readable for both small and large match sets

## What actually happened

Implementation matches the plan, with a few small additions not spelled out
there:

- **Reused the existing `TopList` component directly** for the domain
  breakdown instead of writing a new table — its `{domain, count}` shape
  already matches `top_domains` exactly, so no new list component was
  needed. Its bar-width visualization came for free, and the backend's own
  50-entry cap on `top_domains` bounds the render further on top of that.
- **A dedicated `.simulator-client-list` class, not a reuse of the
  dashboard's `.client-list`.** The dashboard's client list is a 3-column
  grid built for sparklines + a "new device" badge; this list only ever has
  two columns (name, matched/total/pct), so reusing it would leave a stray
  empty grid column. High-impact clients (`pct_of_client_traffic > 30`, the
  spec's SmartFridge threshold) get an amber `.high-impact` count instead of
  the dashboard's unrelated `.disabled` (dimmed) styling, which would have
  visually meant the opposite thing.
- **Error and result state are mutually exclusive** (`setResult(null)` on
  error, `setError(null)` on success) — confirmed in the browser that
  submitting an invalid pattern right after a valid one clears the previous
  results table rather than leaving stale data sitting under the error
  banner.
- Verified the empty-pattern case client-side too: the Simulate button is
  `disabled` while the trimmed pattern is empty, so an empty request can't
  even be sent (the backend's own 400 for it is defense in depth, exercised
  directly via the API in task 1's tests).
