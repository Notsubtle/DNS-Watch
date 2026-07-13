import { useEffect, useState } from "react";
import { api, Anomaly, LatencyHealth } from "../api";

// How far above baseline the current hour is, as a whole-number percentage —
// e.g. current=50, baseline_avg=10 -> "+400%", matching the spec's mockup.
function pctAboveBaseline(a: Anomaly): number {
  if (a.baseline_avg <= 0) return 0;
  return Math.round(((a.current_value - a.baseline_avg) / a.baseline_avg) * 100);
}

function describe(a: Anomaly): string {
  if (a.kind === "silent") return `${a.name} (No activity)`;
  if (a.kind === "nxdomain") return `${a.name} (${a.current_value}% failed lookups)`;
  if (a.kind === "latency") return `${a.name} (${a.current_value}ms resolution latency)`;
  return `${a.name} (+${pctAboveBaseline(a)}% Spike)`;
}

// "nxdomain" reports a rate (%); "latency" reports milliseconds -- neither is
// a queries/hr count -- see api.ts's Anomaly.kind comment.
function statLine(a: Anomaly): string {
  if (a.kind === "nxdomain") return `Baseline: ${a.baseline_avg}% · Current: ${a.current_value}%`;
  if (a.kind === "latency") return `Baseline: ${a.baseline_avg}ms · Current: ${a.current_value}ms`;
  return `Baseline: ${a.baseline_avg}/hr (±${a.baseline_stddev}) · Current: ${a.current_value}/hr`;
}

interface Props {
  anomalies: Anomaly[];
  onSelect: (a: Anomaly) => void;
  onSelectIp: (a: Anomaly) => void;
}

// Same visual pattern as AlertsPanel — reuses its CSS classes directly, since
// the "scannable colored-dot list" look is identical, just a different data
// source and meaning (automatic baseline deviation vs. user-configured rules).
export default function AnomaliesPanel({ anomalies, onSelect, onSelectIp }: Props) {
  // Network-wide resolver latency health (#4) -- a single network-wide fact,
  // deliberately NOT one of the per-client `anomalies` rows above (see
  // db.network_latency_health's module note). Fetched once per mount; this
  // panel already re-mounts on the same poll cadence as `anomalies` via its
  // parent, so no separate polling loop is needed here.
  const [latency, setLatency] = useState<LatencyHealth | null>(null);
  useEffect(() => {
    api.latencyHealth().then(setLatency).catch(() => setLatency(null));
  }, []);

  return (
    <div className="panel alerts-panel">
      <div className="panel-head">
        <h2>
          Network Anomalies
          {anomalies.length > 0 && <span className="alert-count">{anomalies.length}</span>}
        </h2>
      </div>
      {latency?.degraded && (
        <div className="alerts-empty network-latency-warning">
          Network-wide resolution latency is up: {latency.recent_avg_ms}ms recent vs.{" "}
          {latency.baseline_avg_ms}ms baseline over the last 7 days.
        </div>
      )}
      {anomalies.length === 0 ? (
        <div className="alerts-empty">
          No anomalies detected. Devices are behaving within their normal range.
        </div>
      ) : (
        <ul className="alerts-list">
          {anomalies.map((a) => (
            <li
              key={`${a.ip}-${a.kind}`}
              className="alert-item anomaly-item"
              onClick={() => onSelect(a)}
              role="button"
              tabIndex={0}
              title={statLine(a) + (a.presence_note ? ` · ${a.presence_note}` : "")}
            >
              <span
                className={`alert-dot ${a.kind === "silent" || a.kind === "latency" ? "warning" : "critical"}`}
              />
              <span className="alert-msg">{describe(a)}</span>
              <button
                type="button"
                className="alert-meta anomaly-ip-link"
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectIp(a);
                }}
                title="View underlying query activity"
              >
                {a.ip}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
