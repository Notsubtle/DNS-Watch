import { useEffect, useState } from "react";
import { api, ClientDetail, ClientInfo } from "../api";
import SummaryCards from "./SummaryCards";
import TimeSeriesChart from "./TimeSeriesChart";
import TopList from "./TopList";
import QueryTypeBreakdown from "./QueryTypeBreakdown";

const RANGES = [
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "all", label: "All" },
];

const MAX_SLOTS = 3;

// #8: pick 2-3 devices, see their profiles side by side -- "is this new
// gadget behaving like my others, or an outlier?" is hard to answer by
// manually tab-flipping between single-client detail views. Pure frontend
// composition of the existing per-client endpoint called in parallel, one
// call per selected device -- no new backend collection needed.
export default function ClientCompareTab({ clients }: { clients: ClientInfo[] }) {
  const [range, setRange] = useState("24h");
  const [slots, setSlots] = useState<string[]>(["", ""]);
  const [details, setDetails] = useState<Record<string, ClientDetail | null>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedIps = slots.filter(Boolean);

  useEffect(() => {
    if (selectedIps.length === 0) {
      setDetails({});
      return;
    }
    let cancelled = false;
    setLoading(true);
    Promise.all(selectedIps.map((ip) => api.clientDetail(ip, range).then((d) => [ip, d] as const)))
      .then((pairs) => {
        if (cancelled) return;
        setDetails(Object.fromEntries(pairs));
        setError(null);
      })
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIps.join(","), range]);

  function setSlot(index: number, ip: string) {
    setSlots((prev) => {
      const next = [...prev];
      next[index] = ip;
      return next;
    });
  }

  function addSlot() {
    if (slots.length < MAX_SLOTS) setSlots((prev) => [...prev, ""]);
  }

  function removeSlot(index: number) {
    setSlots((prev) => prev.filter((_, i) => i !== index));
  }

  // Domain set-difference (#8's own explicit ask): for each selected device,
  // which of its top domains no OTHER selected device also queried.
  function uniqueDomains(ip: string): string[] {
    const mine = new Set((details[ip]?.top_domains ?? []).map((d) => d.domain).filter(Boolean) as string[]);
    for (const other of selectedIps) {
      if (other === ip) continue;
      for (const d of details[other]?.top_domains ?? []) {
        if (d.domain) mine.delete(d.domain);
      }
    }
    return [...mine];
  }

  return (
    <div className="compare-tab">
      <div className="panel">
        <h2>Client Comparison</h2>
        <p className="modal-sub">
          Compare 2-3 devices side by side — top domains, query-type mix, and activity shape over
          the same window, plus which of each device's top domains no other selected device also
          queried.
        </p>

        <div className="filter-bar">
          {RANGES.map((r) => (
            <button
              key={r.value}
              className={range === r.value ? "active" : ""}
              onClick={() => setRange(r.value)}
            >
              {r.label}
            </button>
          ))}
        </div>

        <div className="compare-slots">
          {slots.map((ip, i) => (
            <div key={i} className="compare-slot-picker">
              <select value={ip} onChange={(e) => setSlot(i, e.target.value)}>
                <option value="">Select a device…</option>
                {clients.map((c) => (
                  <option key={c.ip} value={c.ip}>
                    {c.name} ({c.query_count.toLocaleString()})
                  </option>
                ))}
              </select>
              {slots.length > 2 && (
                <button className="btn-small" onClick={() => removeSlot(i)} aria-label="Remove slot">
                  ×
                </button>
              )}
            </div>
          ))}
          {slots.length < MAX_SLOTS && (
            <button className="btn-small" onClick={addSlot}>
              + Add device
            </button>
          )}
        </div>
      </div>

      {loading && <div className="chart-empty">Loading…</div>}
      {error && <div className="error-banner">{error}</div>}

      {!loading && !error && selectedIps.length > 0 && (
        <div className="compare-grid">
          {selectedIps.map((ip) => {
            const d = details[ip];
            if (!d) return null;
            const unique = uniqueDomains(ip);
            return (
              <div key={ip} className="panel compare-column">
                <h3 title={ip}>{d.name}</h3>
                <SummaryCards summary={d.summary} />
                <TimeSeriesChart data={d.timeseries} loading={false} />
                <TopList title="Top domains" entries={d.top_domains} />
                <QueryTypeBreakdown entries={d.query_types} />
                {unique.length > 0 && (
                  <div className="compare-unique-domains">
                    <h4 className="modal-section">
                      Only {d.name} queried these (of its top domains)
                    </h4>
                    <ul>
                      {unique.slice(0, 10).map((dom) => (
                        <li key={dom}>{dom}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {!loading && !error && selectedIps.length === 0 && (
        <div className="tab-placeholder">Select 2-3 devices above to compare them.</div>
      )}
    </div>
  );
}
