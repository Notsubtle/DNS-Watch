import { QueryLatencyEntry } from "../api";

function formatMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

interface Props {
  entries: QueryLatencyEntry[];
}

// #47: domains ranked by average resolution latency (Pi-hole's own
// reply_time) -- surfaces slow, uncached, or upstream-forwarded lookups a
// per-client view can't show. Empty on Pi-hole schemas that don't carry a
// reply_time column at all (older client-table/plain-TEXT layouts), which
// this panel can't tell apart from "genuinely no slow domains yet" -- so the
// empty state stays neutral rather than claiming a specific reason.
export default function QueryLatencyPanel({ entries }: Props) {
  const max = Math.max(1, ...entries.map((e) => e.avg_reply_ms));
  return (
    <div className="panel">
      <h2>Slowest domains</h2>
      <ul className="top-list">
        {entries.map((e) => {
          const pct = Math.round((e.avg_reply_ms / max) * 100);
          return (
            <li
              key={e.domain}
              style={{
                background: `linear-gradient(90deg, var(--ink-blue-bg) ${pct}%, transparent ${pct}%)`,
              }}
            >
              <span className="name" title={e.domain}>
                {e.domain}
              </span>
              <span className="count" title={`${e.query_count} queries, max ${formatMs(e.max_reply_ms)}`}>
                {formatMs(e.avg_reply_ms)} avg
              </span>
            </li>
          );
        })}
        {entries.length === 0 && <li className="name">No slow domains for this range</li>}
      </ul>
    </div>
  );
}
