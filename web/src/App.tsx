import { useEffect, useRef, useState } from "react";
import {
  AlertEvent,
  Anomaly,
  api,
  ClientActivity,
  ClientInfo,
  Filters,
  QueryRow,
  QueryTypeEntry,
  Summary,
  Tag,
  Timeseries,
  TopEntry,
} from "./api";
import FilterBar from "./components/FilterBar";
import SummaryCards from "./components/SummaryCards";
import QueryTable from "./components/QueryTable";
import TopList from "./components/TopList";
import ClientList from "./components/ClientList";
import TimeSeriesChart from "./components/TimeSeriesChart";
import QueryTypeBreakdown from "./components/QueryTypeBreakdown";
import DrilldownModal from "./components/DrilldownModal";
import ClientDetailModal from "./components/ClientDetailModal";
import AlertsPanel from "./components/AlertsPanel";
import AnomaliesPanel from "./components/AnomaliesPanel";
import AnomalyDetailDrawer from "./components/AnomalyDetailDrawer";
import RulesModal from "./components/RulesModal";
import DeviceNamesModal from "./components/DeviceNamesModal";
import TagsModal from "./components/TagsModal";
import SettingsModal from "./components/SettingsModal";
import TabNav, { View } from "./components/TabNav";
import LiveStreamTab from "./components/LiveStreamTab";
import SimulatorTab from "./components/SimulatorTab";
import ClientHeatmapTab from "./components/ClientHeatmapTab";
import FanoutTab from "./components/FanoutTab";

// The smallest preset range (FilterBar only offers fixed buckets, no
// arbitrary since/until) that fully contains an anomaly's detection window —
// close enough to "jump to when it happened" without introducing exact
// since/until support into the app's filter model just for this feature.
function nearestPresetForAnomaly(a: Anomaly): string {
  const spanSeconds = a.window_until - a.window_since;
  if (spanSeconds <= 15 * 60) return "15m";
  if (spanSeconds <= 60 * 60) return "1h";
  if (spanSeconds <= 24 * 60 * 60) return "24h";
  return "7d";
}

const REFRESH_MS = 5000;
// Anomaly detection operates on hourly buckets, so nothing meaningful changes
// between one 5s dashboard tick and the next — polling it that often is pure
// waste. It also measured ~1.5s per call against the real ~650k-row Cube1
// snapshot (no index on Pi-hole's `client` column to speed it up further, and
// this app must never modify Pi-hole's schema). A slower, independent
// interval matches the alert engine's own 60s default eval cadence
// (ALERT_EVAL_INTERVAL_SECONDS) and keeps this off the fast refresh's
// critical path.
const ANOMALIES_REFRESH_MS = 60000;
const PAGE_SIZE = 200;

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [filters, setFiltersState] = useState<Filters>({
    client: "",
    tag: "",
    domain: "",
    status: "all",
    range: "1h",
  });
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [rows, setRows] = useState<QueryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [topDomains, setTopDomains] = useState<TopEntry[]>([]);
  const [topClients, setTopClients] = useState<ClientActivity[]>([]);
  const [series, setSeries] = useState<Timeseries | null>(null);
  const [queryTypes, setQueryTypes] = useState<QueryTypeEntry[]>([]);
  const [alertEvents, setAlertEvents] = useState<AlertEvent[]>([]);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [drilldown, setDrilldown] = useState<string | null>(null);
  const [clientDetail, setClientDetail] = useState<string | null>(null);
  const [anomalyDetail, setAnomalyDetail] = useState<Anomaly | null>(null);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [deviceNamesOpen, setDeviceNamesOpen] = useState(false);
  const [tagsOpen, setTagsOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sideColRef = useRef<HTMLDivElement>(null);
  const [sideColHeight, setSideColHeight] = useState<number>();

  // Live Query Log should stand exactly as tall as the stacked Top
  // Domains/Top Clients/Query Types column, never taller — so it scrolls
  // internally instead of pushing the page. Grid alone can't express "match
  // this sibling's natural height" when the other column's own content is
  // larger, so we measure it and apply it as an explicit row height.
  useEffect(() => {
    const el = sideColRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      const height = entries[0]?.contentRect.height;
      if (height) setSideColHeight(height);
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Any filter change resets paging back to the first page — the old offset
  // rarely makes sense against a different result set.
  function setFilters(f: Filters) {
    setFiltersState(f);
    setOffset(0);
  }

  // Debounce the domain search so we're not hitting the API on every keystroke
  const [debouncedDomain, setDebouncedDomain] = useState(filters.domain);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedDomain(filters.domain), 300);
    return () => clearTimeout(t);
  }, [filters.domain]);

  const effectiveFilters = { ...filters, domain: debouncedDomain };
  const filtersRef = useRef(effectiveFilters);
  filtersRef.current = effectiveFilters;
  const offsetRef = useRef(offset);
  offsetRef.current = offset;

  useEffect(() => {
    api.clients().then(setClients).catch(() => {});
    api.listTags().then(setTags).catch(() => {});
  }, []);

  // `showLoading` distinguishes user-initiated fetches (filter/page changes),
  // which get a spinner, from the silent 5s background poll, which shouldn't
  // flash the table every tick.
  async function refresh(showLoading: boolean) {
    const f = filtersRef.current;
    const off = offsetRef.current;
    if (showLoading) setLoading(true);
    try {
      const [q, s, td, tc, ts, qt, al] = await Promise.all([
        api.queries(f, PAGE_SIZE, off),
        api.summary(f),
        api.topDomains(f),
        api.clientActivity(f),
        api.timeseries(f),
        api.queryTypes(f),
        api.alerts(),
      ]);
      setRows(q.rows);
      setTotal(q.total);
      setSummary(s);
      setTopDomains(td);
      setTopClients(tc);
      setSeries(ts);
      setQueryTypes(qt);
      setAlertEvents(al.events);
      setError(null);
    } catch (e) {
      setError(
        "Can't reach the DNS Watch backend or Pi-hole's database. Check that the container is " +
          "running and PIHOLE_ETC_PATH points at the right folder. (" + (e as Error).message + ")"
      );
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  // Clicking an anomaly filters the main view to that client, scoped to
  // (approximately) when it happened. Reuses the existing filter state
  // machinery — same as ClientList's/TopList's click-through.
  function handleAnomalySelect(a: Anomaly) {
    setFilters({ ...filters, client: a.ip, tag: "", range: nearestPresetForAnomaly(a) });
  }

  // Clicking the IP text specifically opens the side drawer with the raw
  // query events behind the anomaly, distinct from the row-click filter
  // behavior above.
  function handleAnomalyIpSelect(a: Anomaly) {
    setAnomalyDetail(a);
  }

  // Refresh everything that shows a client name (after a rename/clear in the
  // Manage Device Names modal) — the current dashboard rows/top-clients AND
  // the raw client list FilterBar's dropdown is built from.
  async function reloadClientNames() {
    try {
      api.clients().then(setClients).catch(() => {});
      await refresh(false);
    } catch {
      /* surfaced by the main refresh loop */
    }
  }

  // Refresh the tag list (after a create/delete/membership change in the
  // Manage Tags modal) — FilterBar's dropdown and RulesModal's scope picker
  // both read from this same state.
  function reloadTags() {
    api.listTags().then(setTags).catch(() => {});
  }

  // Re-evaluate alerts on demand (after a rule is added/toggled/removed).
  async function reloadAlerts() {
    try {
      const al = await api.alerts();
      setAlertEvents(al.events);
    } catch {
      /* surfaced by the main refresh loop */
    }
  }

  useEffect(() => {
    if (view !== "dashboard") return;
    refresh(true);
  }, [view, filters.client, filters.tag, filters.status, filters.range, debouncedDomain, offset]);

  useEffect(() => {
    if (!autoRefresh || view !== "dashboard") return;
    const id = setInterval(() => refresh(false), REFRESH_MS);
    return () => clearInterval(id);
  }, [autoRefresh, view, filters.client, filters.tag, filters.status, filters.range, debouncedDomain, offset]);

  // Independent, slower poll for anomalies — see ANOMALIES_REFRESH_MS above
  // for why this isn't part of the main 5s refresh. Also only runs on the
  // dashboard tab — no point polling a widget that isn't on screen, and it
  // keeps the Live Stream tab's own high-frequency polling as the only thing
  // hitting the backend while that tab is active.
  useEffect(() => {
    if (view !== "dashboard") return;
    let cancelled = false;
    function poll() {
      api.anomalies().then((an) => !cancelled && setAnomalies(an)).catch(() => {});
    }
    poll();
    const id = setInterval(poll, ANOMALIES_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [view]);

  return (
    <div className="app">
      <div className="app-header">
        <div>
          <h1>
            <span className="live-dot" />
            DNS Watch
          </h1>
          <div className="subtitle">Live per-client DNS activity from Pi-hole</div>
        </div>
        <div className="header-actions">
          <button className="btn-small" onClick={() => setDeviceNamesOpen(true)}>
            🏷 Name Devices
          </button>
          <button className="btn-small" onClick={() => setTagsOpen(true)}>
            🏷 Manage Tags
          </button>
          <button className="btn-small header-settings" onClick={() => setSettingsOpen(true)}>
            ⚙ Settings
          </button>
        </div>
      </div>

      <TabNav view={view} onChange={setView} />

      {view === "dashboard" && (
        <>
          {error && <div className="error-banner">{error}</div>}

          <FilterBar
            filters={filters}
            onChange={setFilters}
            clients={clients}
            tags={tags}
            autoRefresh={autoRefresh}
            onToggleAutoRefresh={() => setAutoRefresh((v) => !v)}
            csvHref={api.csvUrl(effectiveFilters)}
          />

          <SummaryCards summary={summary} />

          <AnomaliesPanel
            anomalies={anomalies}
            onSelect={handleAnomalySelect}
            onSelectIp={handleAnomalyIpSelect}
          />

          <AlertsPanel events={alertEvents} onManageRules={() => setRulesOpen(true)} />

          <TimeSeriesChart data={series} loading={loading} />

          <div
            className="main-grid"
            style={sideColHeight ? { height: `${sideColHeight}px` } : undefined}
          >
            <QueryTable
              rows={rows}
              total={total}
              offset={offset}
              pageSize={PAGE_SIZE}
              loading={loading}
              onPrev={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              onNext={() => setOffset((o) => o + PAGE_SIZE)}
            />
            <div ref={sideColRef} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <TopList title="Top domains" entries={topDomains} onSelect={setDrilldown} />
              <ClientList clients={topClients} onSelect={setClientDetail} />
              <QueryTypeBreakdown entries={queryTypes} />
            </div>
          </div>

          {drilldown && (
            <DrilldownModal
              domain={drilldown}
              filters={effectiveFilters}
              onClose={() => setDrilldown(null)}
            />
          )}

          {clientDetail && (
            <ClientDetailModal
              ip={clientDetail}
              range={effectiveFilters.range}
              onClose={() => setClientDetail(null)}
            />
          )}

          {rulesOpen && (
            <RulesModal onClose={() => setRulesOpen(false)} onChange={reloadAlerts} tags={tags} />
          )}
        </>
      )}

      {view === "stream" && <LiveStreamTab />}
      {view === "simulator" && <SimulatorTab />}
      {view === "heatmap" && <ClientHeatmapTab clients={clients} />}
      {view === "fanout" && <FanoutTab />}

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}

      {deviceNamesOpen && (
        <DeviceNamesModal onClose={() => setDeviceNamesOpen(false)} onChange={reloadClientNames} />
      )}

      {tagsOpen && (
        <TagsModal onClose={() => setTagsOpen(false)} onChange={reloadTags} clients={clients} />
      )}

      <AnomalyDetailDrawer anomaly={anomalyDetail} onClose={() => setAnomalyDetail(null)} />
    </div>
  );
}
