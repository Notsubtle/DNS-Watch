# Shared prerequisite: tab navigation shell

Required by: [Feature 2 — Live Stream](../02-live-stream/README.md),
[Feature 3 — Blocklist Simulator](../03-blocklist-simulator/README.md),
[Feature 4 — Client Heatmap](../04-client-heatmap/README.md)

## Goal

`App.tsx` today is a single page — no router, no tabs, just modals layered on
top of one dashboard view. Three features need a dedicated page. Add the
smallest possible navigation shell rather than pulling in a routing library.

## Implementation plan

1. Add a `view` state to `App.tsx`:
   ```ts
   type View = "dashboard" | "stream" | "simulator" | "heatmap";
   const [view, setView] = useState<View>("dashboard");
   ```
2. New `web/src/components/TabNav.tsx` — simple button row (Dashboard / Live
   Stream / Blocklist Simulator / Client Heatmaps), rendered in the app
   header area next to the existing Settings button.
3. Wrap the *existing* dashboard JSX (everything currently in `App.tsx`'s
   `return`) in `{view === "dashboard" && (...)}` — zero behavior change when
   on that tab, by construction.
4. Each new tab's content is a single top-level component
   (`LiveStreamTab.tsx`, `SimulatorTab.tsx`, `ClientHeatmapTab.tsx`) rendered
   conditionally the same way. Each feature owns its own component; this
   sub-task only wires the switch.
5. **Pause the dashboard's background polling when it's not the active
   tab.** The existing `refresh()` 5s interval in `App.tsx` should only run
   while `view === "dashboard"` — otherwise it keeps hitting the backend
   uselessly while the user is on, say, the Live Stream tab (which has its
   *own* 1-2s polling loop — see Feature 2). Gate the existing
   `useEffect(() => { ... setInterval ... }, [autoRefresh, ...])` on
   `view === "dashboard"` too.

## Design decision

Switching tabs **unmounts** the previous tab's content (simplest React
behavior, no manual state preservation). This is intentionally fine for every
consumer: Feature 2's stream buffer is explicitly volatile already, Feature
3's simulator has no persisted state to lose, Feature 4's heatmap re-fetches
cheaply. Don't build a keep-alive/cache layer for this — not asked for by any
of the three features.

## Definition of done

- [x] `TabNav.tsx` renders and switches `view`
- [x] Dashboard tab behavior is pixel-for-pixel unchanged from before this change
- [x] Dashboard's 5s poll (and the 60s anomalies poll) stop firing while another tab is active, resume when switching back — confirmed via network log: zero new requests over 18+s on the Live Stream tab, resumed immediately on switching back to Dashboard
- [x] No console errors switching rapidly between tabs

Implementation note: `simulator` and `heatmap` tabs render a lightweight inline `.tab-placeholder` div ("coming soon") rather than dedicated component files, since Features 3/4 aren't built yet — avoids throwaway files. Each will get its real component when its feature starts.
