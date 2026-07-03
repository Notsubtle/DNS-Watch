import { Summary } from "../api";

export default function SummaryCards({ summary }: { summary: Summary | null }) {
  if (!summary) return null;
  return (
    <div className="summary-cards">
      <div className="card">
        <div className="label">Total queries</div>
        <div className="value">{summary.total_queries.toLocaleString()}</div>
      </div>
      <div className="card">
        <div className="label">Blocked</div>
        <div className="value blocked">{summary.blocked_pct}%</div>
      </div>
      <div className="card">
        <div className="label">Unique clients</div>
        <div className="value">{summary.unique_clients}</div>
      </div>
      <div className="card">
        <div className="label">Unique domains</div>
        <div className="value">{summary.unique_domains}</div>
      </div>
    </div>
  );
}
