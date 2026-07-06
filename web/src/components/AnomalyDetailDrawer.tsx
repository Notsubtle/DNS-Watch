import { useEffect, useState } from "react";
import { api, Anomaly, QueryRow } from "../api";

function fmtDateTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

function describeKind(kind: Anomaly["kind"]): string {
  return kind === "silent" ? "Silent — no activity" : "Spike — unusual volume";
}

interface Props {
  anomaly: Anomaly | null;
  onClose: () => void;
}

// Side drawer (not a modal) showing the actual query events behind a single
// anomaly row: baseline vs. current stats up top, then the raw /api/queries
// rows for that client scoped exactly to window_since..window_until — this
// is the only place in the anomaly flow that surfaces per-event detail,
// since detect_anomalies() itself only returns aggregate stats.
export default function AnomalyDetailDrawer({ anomaly, onClose }: Props) {
  const [rows, setRows] = useState<QueryRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Keep rendering the last-opened anomaly's content while the panel slides
  // out — if we unmounted on `anomaly == null` immediately, the close
  // transition would have nothing left to animate.
  const [displayed, setDisplayed] = useState<Anomaly | null>(anomaly);

  useEffect(() => {
    if (anomaly) setDisplayed(anomaly);
  }, [anomaly]);

  useEffect(() => {
    if (!anomaly) return;
    let cancelled = false;
    setLoading(true);
    api
      .anomalyQueries(anomaly.ip, anomaly.window_since, anomaly.window_until)
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
  }, [anomaly]);

  useEffect(() => {
    if (!anomaly) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [anomaly, onClose]);

  const open = !!anomaly;
  const a = displayed;

  return (
    <div className={`drawer${open ? " drawer-open" : ""}`} aria-hidden={!open}>
      {a && (
        <div className="drawer-panel" role="dialog" aria-modal="false">
          <div className="drawer-head">
            <div>
              <h2 title={a.ip}>{a.name}</h2>
              <span className="modal-ip">{a.ip}</span>
            </div>
            <button className="modal-close" onClick={onClose} aria-label="Close">
              ×
            </button>
          </div>

          <div className={`drawer-kind ${a.kind === "silent" ? "warning" : "critical"}`}>
            {describeKind(a.kind)}
          </div>

          <div className="drawer-stats">
            <div>
              <span className="drawer-stat-label">Baseline</span>
              <span className="drawer-stat-value">
                {a.baseline_avg}/hr (±{a.baseline_stddev})
              </span>
            </div>
            <div>
              <span className="drawer-stat-label">Current</span>
              <span className="drawer-stat-value">{a.current_value}/hr</span>
            </div>
          </div>

          <div className="drawer-window">
            {fmtDateTime(a.window_since)} – {fmtDateTime(a.window_until)}
          </div>

          {a.presence_note && <div className="drawer-window">{a.presence_note}</div>}

          <h3 className="modal-section">Query activity in this window</h3>

          {loading && <div className="chart-empty">Loading…</div>}
          {error && <div className="error-banner">{error}</div>}

          {!loading && !error && (
            <>
              {rows.length === 0 ? (
                <div className="chart-empty">No queries recorded for this client in this window.</div>
              ) : (
                <>
                  <div className="modal-sub">
                    {total.toLocaleString()} queries in this window
                    {rows.length < total ? ` (showing latest ${rows.length})` : ""}
                  </div>
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((r, i) => (
                        <tr key={`${r.timestamp}-${i}`}>
                          <td>{fmtTime(r.timestamp)}</td>
                          <td title={r.domain}>{r.domain}</td>
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
            </>
          )}
        </div>
      )}
    </div>
  );
}
