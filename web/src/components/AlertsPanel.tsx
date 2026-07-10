import { useState } from "react";
import { api, AlertEvent } from "../api";

function relTime(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// Snooze presets (#42): the rule/dedup_key keep firing on their own schedule
// forever, so these are "give it a rest for a while" durations, not a
// permanent mute -- there's no snooze-until-manually-cleared option here on
// purpose, to avoid a silently-forgotten-forever alert.
const SNOOZE_OPTIONS = [
  { label: "1h", seconds: 3600 },
  { label: "24h", seconds: 86400 },
  { label: "7d", seconds: 7 * 86400 },
];

interface Props {
  events: AlertEvent[];
  onManageRules: () => void;
}

export default function AlertsPanel({ events, onManageRules }: Props) {
  // Tracks snoozes applied THIS session, keyed by dedup_key so every event
  // sharing that recurrence (not just the one clicked) reflects it -- purely
  // local optimism; the backend is the actual source of truth on the next
  // /api/alerts poll, which simply won't re-emit a snoozed dedup_key.
  const [snoozed, setSnoozed] = useState<Record<string, number>>({});
  const [error, setError] = useState<string | null>(null);

  async function handleSnooze(e: AlertEvent, seconds: number) {
    setError(null);
    try {
      const until = Math.floor(Date.now() / 1000) + seconds;
      await api.snoozeEvent(e.id, until);
      setSnoozed((prev) => ({ ...prev, [e.dedup_key]: until }));
    } catch (err) {
      setError((err as Error).message);
    }
  }

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
      {error && <div className="error-banner">{error}</div>}
      {events.length === 0 ? (
        <div className="alerts-empty">
          No alerts. Add a rule to watch for query spikes, new devices, or specific domains.
        </div>
      ) : (
        <ul className="alerts-list">
          {events.map((e) => {
            const snoozedUntil = snoozed[e.dedup_key];
            return (
              <li key={e.id} className={`alert-item ${e.severity}`}>
                <span className={`alert-dot ${e.severity}`} />
                <span className="alert-msg">{e.message}</span>
                <span className="alert-meta">
                  {e.rule_name} · {relTime(e.created_at)}
                </span>
                {snoozedUntil ? (
                  <span className="alert-snoozed" title="This recurrence won't re-fire until then">
                    Snoozed until {new Date(snoozedUntil * 1000).toLocaleString()}
                  </span>
                ) : (
                  <select
                    className="alert-snooze-select"
                    value=""
                    title="Snooze this specific recurrence without disabling the rule"
                    onChange={(ev) => {
                      const seconds = Number(ev.target.value);
                      if (seconds) handleSnooze(e, seconds);
                    }}
                  >
                    <option value="">Snooze…</option>
                    {SNOOZE_OPTIONS.map((o) => (
                      <option key={o.label} value={o.seconds}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
