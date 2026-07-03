import { ClientActivity } from "../api";
import Sparkline from "./Sparkline";

// A client counts as "new" if its first-ever query landed within this window.
const NEW_DEVICE_WINDOW_S = 24 * 3600;

function isNew(firstSeen: number | null): boolean {
  if (!firstSeen) return false;
  return Date.now() / 1000 - firstSeen < NEW_DEVICE_WINDOW_S;
}

interface Props {
  clients: ClientActivity[];
  onSelect?: (ip: string) => void;
}

export default function ClientList({ clients, onSelect }: Props) {
  const max = Math.max(1, ...clients.map((c) => c.count));
  return (
    <div className="panel">
      <h2>Top clients</h2>
      <ul className={`client-list${onSelect ? " clickable" : ""}`}>
        {clients.map((c) => {
          const pct = Math.round((c.count / max) * 100);
          return (
            <li
              key={c.ip}
              style={{
                background: `linear-gradient(90deg, var(--ink-blue-bg) ${pct}%, transparent ${pct}%)`,
              }}
              onClick={onSelect ? () => onSelect(c.ip) : undefined}
              role={onSelect ? "button" : undefined}
              tabIndex={onSelect ? 0 : undefined}
              onKeyDown={
                onSelect ? (ev) => (ev.key === "Enter" || ev.key === " ") && onSelect(c.ip) : undefined
              }
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
