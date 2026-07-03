import { TopEntry } from "../api";

export default function TopList({ title, entries }: { title: string; entries: TopEntry[] }) {
  const max = Math.max(1, ...entries.map((e) => e.count));
  return (
    <div className="panel">
      <h2>{title}</h2>
      <ul className="top-list">
        {entries.map((e, i) => {
          const label = e.domain ?? e.name ?? e.ip ?? "?";
          const pct = Math.round((e.count / max) * 100);
          return (
            <li
              key={`${label}-${i}`}
              style={{
                background: `linear-gradient(90deg, var(--ink-blue-bg) ${pct}%, transparent ${pct}%)`,
              }}
            >
              <span className="name" title={label}>
                {label}
              </span>
              <span className="count">{e.count}</span>
            </li>
          );
        })}
        {entries.length === 0 && <li className="name">No data yet</li>}
      </ul>
    </div>
  );
}
