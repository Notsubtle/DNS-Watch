import { TopEntry } from "../api";

type TopListEntry = {
  domain?: string | null;
  ip?: string | null;
  name?: string | null;
  count?: number;
};

interface Props<T extends TopListEntry = TopEntry> {
  title: string;
  entries: T[];
  // When provided, rows become clickable and call back with the entry's label
  // (used to open the domain drill-down from "Top domains").
  onSelect?: (label: string) => void;
  getLabel?: (entry: T) => string;
  getSubtitle?: (entry: T) => string | null;
  getCount?: (entry: T) => number;
}

export default function TopList<T extends TopListEntry = TopEntry>({
  title,
  entries,
  onSelect,
  getLabel,
  getSubtitle,
  getCount,
}: Props<T>) {
  const countFor = getCount ?? ((entry: T) => entry.count ?? 0);
  const max = Math.max(1, ...entries.map(countFor));
  return (
    <div className="panel">
      <h2>{title}</h2>
      <ul className={`top-list${onSelect ? " clickable" : ""}`}>
        {entries.map((e, i) => {
          const label = getLabel ? getLabel(e) : e.domain ?? e.name ?? e.ip ?? "?";
          const subtitle = getSubtitle?.(e);
          const count = countFor(e);
          const pct = Math.round((count / max) * 100);
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
              <span className="name" title={subtitle ? `${label} ${subtitle}` : label}>
                <span>{label}</span>
                {subtitle && <span className="subname">{subtitle}</span>}
              </span>
              <span className="count">{count}</span>
            </li>
          );
        })}
        {entries.length === 0 && <li className="name">No data yet</li>}
      </ul>
    </div>
  );
}
