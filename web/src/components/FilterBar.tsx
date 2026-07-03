import { ClientInfo, Filters } from "../api";

interface Props {
  filters: Filters;
  onChange: (f: Filters) => void;
  clients: ClientInfo[];
  autoRefresh: boolean;
  onToggleAutoRefresh: () => void;
}

const RANGES = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "all", label: "All" },
];

export default function FilterBar({ filters, onChange, clients, autoRefresh, onToggleAutoRefresh }: Props) {
  return (
    <div className="filter-bar">
      <select
        value={filters.client}
        onChange={(e) => onChange({ ...filters, client: e.target.value })}
      >
        <option value="">All clients</option>
        {clients.map((c) => (
          <option key={c.ip} value={c.ip}>
            {c.name} ({c.query_count})
          </option>
        ))}
      </select>

      <input
        type="text"
        placeholder="Search domain…"
        value={filters.domain}
        onChange={(e) => onChange({ ...filters, domain: e.target.value })}
      />

      <select
        value={filters.status}
        onChange={(e) => onChange({ ...filters, status: e.target.value })}
      >
        <option value="all">All statuses</option>
        <option value="allowed">Allowed</option>
        <option value="blocked">Blocked</option>
      </select>

      {RANGES.map((r) => (
        <button
          key={r.value}
          className={filters.range === r.value ? "active" : ""}
          onClick={() => onChange({ ...filters, range: r.value })}
        >
          {r.label}
        </button>
      ))}

      <div className="spacer" />

      <button className={autoRefresh ? "active" : ""} onClick={onToggleAutoRefresh}>
        {autoRefresh ? "● Live" : "Paused"}
      </button>
    </div>
  );
}
