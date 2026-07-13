import { Anomaly } from "../api";

// How far above baseline the current hour is, as a whole-number percentage —
// e.g. current=50, baseline_avg=10 -> "+400%", matching the spec's mockup.
function pctAboveBaseline(a: Anomaly): number {
  if (a.baseline_avg <= 0) return 0;
  return Math.round(((a.current_value - a.baseline_avg) / a.baseline_avg) * 100);
}

function describe(a: Anomaly): string {
  if (a.kind === "silent") return `${a.name} (No activity)`;
  if (a.kind === "nxdomain") return `${a.name} (${a.current_value}% failed lookups)`;
  return `${a.name} (+${pctAboveBaseline(a)}% Spike)`;
}

// "nxdomain" reports a rate (%), not a queries/hr count -- see api.ts's Anomaly.kind comment.
function statLine(a: Anomaly): string {
  if (a.kind === "nxdomain") return `Baseline: ${a.baseline_avg}% · Current: ${a.current_value}%`;
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
  return (
    <div className="panel alerts-panel">
      <div className="panel-head">
        <h2>
          Network Anomalies
          {anomalies.length > 0 && <span className="alert-count">{anomalies.length}</span>}
        </h2>
      </div>
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
              <span className={`alert-dot ${a.kind === "silent" ? "warning" : "critical"}`} />
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
