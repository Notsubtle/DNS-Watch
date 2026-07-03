import { QueryRow } from "../api";

function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

export default function QueryTable({ rows }: { rows: QueryRow[] }) {
  return (
    <div className="panel">
      <h2>Live query log ({rows.length})</h2>
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
    </div>
  );
}
