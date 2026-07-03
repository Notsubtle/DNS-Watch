import { useEffect, useRef, useState } from "react";
import {
  api,
  ClientInfo,
  Filters,
  QueryRow,
  QueryTypeEntry,
  Summary,
  Timeseries,
  TopEntry,
} from "./api";
import FilterBar from "./components/FilterBar";
import SummaryCards from "./components/SummaryCards";
import QueryTable from "./components/QueryTable";
import TopList from "./components/TopList";
import TimeSeriesChart from "./components/TimeSeriesChart";
import QueryTypeBreakdown from "./components/QueryTypeBreakdown";
import DrilldownModal from "./components/DrilldownModal";

const REFRESH_MS = 5000;
const PAGE_SIZE = 200;

export default function App() {
  const [filters, setFiltersState] = useState<Filters>({
    client: "",
    domain: "",
    status: "all",
    range: "1h",
  });
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [rows, setRows] = useState<QueryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [topDomains, setTopDomains] = useState<TopEntry[]>([]);
  const [topClients, setTopClients] = useState<TopEntry[]>([]);
  const [series, setSeries] = useState<Timeseries | null>(null);
  const [queryTypes, setQueryTypes] = useState<QueryTypeEntry[]>([]);
  const [drilldown, setDrilldown] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

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
  }, []);

  // `showLoading` distinguishes user-initiated fetches (filter/page changes),
  // which get a spinner, from the silent 5s background poll, which shouldn't
  // flash the table every tick.
  async function refresh(showLoading: boolean) {
    const f = filtersRef.current;
    const off = offsetRef.current;
    if (showLoading) setLoading(true);
    try {
      const [q, s, td, tc, ts, qt] = await Promise.all([
        api.queries(f, PAGE_SIZE, off),
        api.summary(f),
        api.topDomains(f),
        api.topClients(f),
        api.timeseries(f),
        api.queryTypes(f),
      ]);
      setRows(q.rows);
      setTotal(q.total);
      setSummary(s);
      setTopDomains(td);
      setTopClients(tc);
      setSeries(ts);
      setQueryTypes(qt);
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

  useEffect(() => {
    refresh(true);
  }, [filters.client, filters.status, filters.range, debouncedDomain, offset]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => refresh(false), REFRESH_MS);
    return () => clearInterval(id);
  }, [autoRefresh, filters.client, filters.status, filters.range, debouncedDomain, offset]);

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
      </div>

      {error && <div className="error-banner">{error}</div>}

      <FilterBar
        filters={filters}
        onChange={setFilters}
        clients={clients}
        autoRefresh={autoRefresh}
        onToggleAutoRefresh={() => setAutoRefresh((v) => !v)}
        csvHref={api.csvUrl(effectiveFilters)}
      />

      <SummaryCards summary={summary} />

      <TimeSeriesChart data={series} loading={loading} />

      <div className="main-grid">
        <QueryTable
          rows={rows}
          total={total}
          offset={offset}
          pageSize={PAGE_SIZE}
          loading={loading}
          onPrev={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
          onNext={() => setOffset((o) => o + PAGE_SIZE)}
        />
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <TopList title="Top domains" entries={topDomains} onSelect={setDrilldown} />
          <TopList title="Top clients" entries={topClients} />
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
    </div>
  );
}
