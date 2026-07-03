import { useEffect, useMemo, useState } from "react";
import { api, Filters, QueryRow } from "../api";

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

interface Props {
  domain: string;
  filters: Filters;
  onClose: () => void;
}

// Drill into a single domain: who's querying it and the most recent hits,
// scoped to the current time range. Reuses the paged /api/queries endpoint.
export default function DrilldownModal({ domain, filters, onClose }: Props) {
  const [rows, setRows] = useState<QueryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    // Ignore the client/domain from the ambient filters here — we want this
    // exact domain across all clients, within the same range.
    const f: Filters = { client: "", domain, status: "all", range: filters.range };
    api
      .queries(f, 500, 0)
      .then((r) => {
        if (cancelled) return;
        setRows(r.rows);
        setTotal(r.total);
        setError(null);
      })
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [domain, filters.range]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const byClient = useMemo(() => {
    const m = new Map<string, { name: string; count: number; blocked: number }>();
    for (const r of rows) {
      const cur = m.get(r.client_ip) ?? { name: r.client_name, count: 0, blocked: 0 };
      cur.count += 1;
      if (r.status === "blocked") cur.blocked += 1;
      m.set(r.client_ip, cur);
    }
    return [...m.entries()].sort((a, b) => b[1].count - a[1].count);
  }, [rows]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2 title={domain}>{domain}</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {loading && <div className="chart-empty">Loading…</div>}
        {error && <div className="error-banner">{error}</div>}

        {!loading && !error && (
          <>
            <div className="modal-sub">
              {total.toLocaleString()} queries in the last {filters.range} · {byClient.length} client
              {byClient.length === 1 ? "" : "s"}
              {rows.length < total ? ` (showing latest ${rows.length})` : ""}
            </div>

            <h3 className="modal-section">By client</h3>
            <ul className="top-list">
              {byClient.map(([ip, v]) => (
                <li key={ip}>
                  <span className="name" title={ip}>
                    {v.name}
                    {v.blocked > 0 && <span className="status-pill blocked mini">{v.blocked} blocked</span>}
                  </span>
                  <span className="count">{v.count}</span>
                </li>
              ))}
              {byClient.length === 0 && <li className="name">No matching queries.</li>}
            </ul>

            <h3 className="modal-section">Recent</h3>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Client</th>
                  <th>Type</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 50).map((r, i) => (
                  <tr key={`${r.timestamp}-${i}`}>
                    <td>{formatTime(r.timestamp)}</td>
                    <td title={r.client_ip}>{r.client_name}</td>
                    <td>{r.query_type}</td>
                    <td>
                      <span className={`status-pill ${r.status}`}>{r.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
