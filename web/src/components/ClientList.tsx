import { ClientActivity } from "../api";
import Sparkline from "./Sparkline";

// A client counts as "new" if its first-ever query landed within this window.
const NEW_DEVICE_WINDOW_S = 24 * 3600;

function isNew(firstSeen: number | null): boolean {
  if (!firstSeen) return false;
  return Date.now() / 1000 - firstSeen < NEW_DEVICE_WINDOW_S;
}

export default function ClientList({ clients }: { clients: ClientActivity[] }) {
  const max = Math.max(1, ...clients.map((c) => c.count));
  return (
    <div className="panel">
      <h2>Top clients</h2>
      <ul className="client-list">
        {clients.map((c) => {
          const pct = Math.round((c.count / max) * 100);
          return (
            <li
              key={c.ip}
              style={{
                background: `linear-gradient(90deg, var(--ink-blue-bg) ${pct}%, transparent ${pct}%)`,
              }}
            >
              <span className="name" title={c.ip}>
                {c.name}
                {isNew(c.first_seen) && <span className="new-badge">NEW</span>}
              </span>
              <Sparkline data={c.sparkline} />
              <span className="count">{c.count.toLocaleString()}</span>
            </li>
          );
        })}
        {clients.length === 0 && <li className="name">No data yet</li>}
      </ul>
    </div>
  );
}
