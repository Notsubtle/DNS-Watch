import { AlertEvent } from "../api";

function relTime(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

interface Props {
  events: AlertEvent[];
  onManageRules: () => void;
}

export default function AlertsPanel({ events, onManageRules }: Props) {
  return (
    <div className="panel alerts-panel">
      <div className="panel-head">
        <h2>
          Alerts
          {events.length > 0 && <span className="alert-count">{events.length}</span>}
        </h2>
        <button className="btn-small" onClick={onManageRules}>
          Manage rules
        </button>
      </div>
      {events.length === 0 ? (
        <div className="alerts-empty">
          No alerts. Add a rule to watch for query spikes, new devices, or specific domains.
        </div>
      ) : (
        <ul className="alerts-list">
          {events.map((e) => (
            <li key={e.id} className={`alert-item ${e.severity}`}>
              <span className={`alert-dot ${e.severity}`} />
              <span className="alert-msg">{e.message}</span>
              <span className="alert-meta">
                {e.rule_name} · {relTime(e.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
