import { QueryRow } from "../api";

function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

interface Props {
  rows: QueryRow[];
  total: number;
  offset: number;
  pageSize: number;
  loading: boolean;
  onPrev: () => void;
  onNext: () => void;
}

export default function QueryTable({ rows, total, offset, pageSize, loading, onPrev, onNext }: Props) {
  const start = total === 0 ? 0 : offset + 1;
  const end = offset + rows.length;
  const hasPrev = offset > 0;
  const hasNext = offset + pageSize < total;

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>
          Live query log
          {loading && <span className="spinner" aria-label="Loading" />}
        </h2>
        <span className="row-count">
          {total > 0 ? `${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()}` : "0 results"}
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Client</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.timestamp}-${r.domain}-${i}`}>
              <td>{formatTime(r.timestamp)}</td>
              <td title={r.client_ip}>{r.client_name}</td>
              <td title={r.domain}>{r.domain}</td>
              <td>{r.query_type}</td>
              <td>
                <span className={`status-pill ${r.status}`}>{r.status}</span>
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={5} style={{ color: "var(--ink-faint)", fontFamily: "var(--font-sans)" }}>
                No queries match the current filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {total > pageSize && (
        <div className="pager">
          <button onClick={onPrev} disabled={!hasPrev || loading}>
            ← Newer
          </button>
          <span className="pager-info">
            Page {Math.floor(offset / pageSize) + 1} of {Math.max(1, Math.ceil(total / pageSize))}
          </span>
          <button onClick={onNext} disabled={!hasNext || loading}>
            Older →
          </button>
        </div>
      )}
    </div>
  );
}
