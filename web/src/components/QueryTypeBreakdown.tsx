import { QueryTypeEntry } from "../api";

export default function QueryTypeBreakdown({ entries }: { entries: QueryTypeEntry[] }) {
  const total = entries.reduce((sum, e) => sum + e.count, 0);
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Query types</h2>
      </div>
      {entries.length === 0 && <div className="chart-empty">No queries.</div>}
      <ul className="type-list">
        {entries.map((e) => {
          const pct = total ? (e.count / total) * 100 : 0;
          return (
            <li key={e.type_code} className="type-row">
              <span className="type-name">{e.type}</span>
              <span className="type-bar-track">
                <span className="type-bar-fill" style={{ width: `${pct}%` }} />
              </span>
              <span className="type-count">{e.count.toLocaleString()}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
