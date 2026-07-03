import { TopEntry } from "../api";

interface Props {
  title: string;
  entries: TopEntry[];
  // When provided, rows become clickable and call back with the entry's label
  // (used to open the domain drill-down from "Top domains").
  onSelect?: (label: string) => void;
}

export default function TopList({ title, entries, onSelect }: Props) {
  const max = Math.max(1, ...entries.map((e) => e.count));
  return (
    <div className="panel">
      <h2>{title}</h2>
      <ul className={`top-list${onSelect ? " clickable" : ""}`}>
        {entries.map((e, i) => {
          const label = e.domain ?? e.name ?? e.ip ?? "?";
          const pct = Math.round((e.count / max) * 100);
          return (
            <li
              key={`${label}-${i}`}
              style={{
                background: `linear-gradient(90deg, var(--ink-blue-bg) ${pct}%, transparent ${pct}%)`,
              }}
              onClick={onSelect ? () => onSelect(label) : undefined}
              role={onSelect ? "button" : undefined}
              tabIndex={onSelect ? 0 : undefined}
              onKeyDown={
                onSelect
                  ? (ev) => {
                      if (ev.key === "Enter" || ev.key === " ") onSelect(label);
                    }
                  : undefined
              }
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
