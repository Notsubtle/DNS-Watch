import { useEffect, useState } from "react";
import { api, QueryRow } from "../api";

const WEEKDAY_NAMES = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function formatHourRange(hour: number): string {
  const pad = (h: number) => String(h).padStart(2, "0");
  return `${pad(hour)}:00–${pad((hour + 1) % 24)}:00`;
}

interface Props {
  // Exactly one of ip/tag is set -- tag (#7) drills into a tag-scoped
  // heatmap cell (multi-client-aware: a Client column is shown) instead of
  // a single client's.
  ip?: string;
  tag?: string;
  clientName: string;
  weekday: number;
  hour: number;
  onClose: () => void;
}

// Modeled on DrilldownModal.tsx's fetch-on-mount / loading-error / Escape-to-
// close / capped-table pattern, scoped to one heatmap cell instead of one domain.
export default function HeatmapCellModal({ ip, tag, clientName, weekday, hour, onClose }: Props) {
  const [rows, setRows] = useState<QueryRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const req = tag ? api.tagHeatmapCell(tag, weekday, hour) : api.clientHeatmapCell(ip!, weekday, hour);
    req
      .then((r) => {
        if (cancelled) return;
        setRows(r);
        setError(null);
      })
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [ip, tag, weekday, hour]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2 title={ip}>
            {clientName} — {WEEKDAY_NAMES[weekday]} {formatHourRange(hour)}
          </h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {loading && <div className="chart-empty">Loading…</div>}
        {error && <div className="error-banner">{error}</div>}

        {!loading && !error && (
          <>
            <div className="modal-sub">
              {rows.length.toLocaleString()} {rows.length === 1 ? "query" : "queries"} in this window
              {rows.length > 50 ? ` (showing latest 50)` : ""}
            </div>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  {tag && <th>Client</th>}
                  <th>Domain</th>
                  <th>Type</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, 50).map((r, i) => (
                  <tr key={`${r.timestamp}-${i}`}>
                    <td>{formatTime(r.timestamp)}</td>
                    {tag && <td title={r.client_ip}>{r.client_name}</td>}
                    <td title={r.domain}>{r.domain}</td>
                    <td>{r.query_type}</td>
                    <td>
                      <span className={`status-pill ${r.status}`}>{r.status}</span>
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={tag ? 5 : 4}>No queries in this window.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  );
}
