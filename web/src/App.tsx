import { useEffect, useRef, useState } from "react";
import { api, ClientInfo, Filters, QueryRow, Summary, TopEntry } from "./api";
import FilterBar from "./components/FilterBar";
import SummaryCards from "./components/SummaryCards";
import QueryTable from "./components/QueryTable";
import TopList from "./components/TopList";

const REFRESH_MS = 5000;

export default function App() {
  const [filters, setFilters] = useState<Filters>({
    client: "",
    domain: "",
    status: "all",
    range: "1h",
  });
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [rows, setRows] = useState<QueryRow[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [topDomains, setTopDomains] = useState<TopEntry[]>([]);
  const [topClients, setTopClients] = useState<TopEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Debounce the domain search so we're not hitting the API on every keystroke
  const [debouncedDomain, setDebouncedDomain] = useState(filters.domain);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedDomain(filters.domain), 300);
    return () => clearTimeout(t);
  }, [filters.domain]);

  const effectiveFilters = { ...filters, domain: debouncedDomain };
  const filtersRef = useRef(effectiveFilters);
  filtersRef.current = effectiveFilters;

  useEffect(() => {
    api.clients().then(setClients).catch(() => {});
  }, []);

  async function refresh() {
    const f = filtersRef.current;
    try {
      const [q, s, td, tc] = await Promise.all([
        api.queries(f),
        api.summary(f),
        api.topDomains(f),
        api.topClients(f),
      ]);
      setRows(q);
      setSummary(s);
      setTopDomains(td);
      setTopClients(tc);
      setError(null);
    } catch (e) {
      setError(
        "Can't reach the DNS Watch backend or Pi-hole's database. Check that the container is " +
          "running and PIHOLE_ETC_PATH points at the right folder. (" + (e as Error).message + ")"
      );
    }
  }

  useEffect(() => {
    refresh();
  }, [filters.client, filters.status, filters.range, debouncedDomain]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(id);
  }, [autoRefresh, filters.client, filters.status, filters.range, debouncedDomain]);

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
      />

      <SummaryCards summary={summary} />

      <div className="main-grid">
        <QueryTable rows={rows} />
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <TopList title="Top domains" entries={topDomains} />
          <TopList title="Top clients" entries={topClients} />
        </div>
      </div>
    </div>
  );
}
