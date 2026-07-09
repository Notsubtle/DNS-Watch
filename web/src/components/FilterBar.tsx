import { useMemo, useState } from "react";
import { ClientInfo, Filters } from "../api";

interface Props {
  filters: Filters;
  onChange: (f: Filters) => void;
  clients: ClientInfo[];
  autoRefresh: boolean;
  onToggleAutoRefresh: () => void;
  csvHref: string;
}

const RANGES = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "all", label: "All" },
];

// Mirrors DeviceNamesModal's vendorLabel so a vendor search can match the
// same "private MAC"/"unknown vendor" text the user actually sees elsewhere,
// not just clients with a resolved vendor name.
function vendorLabel(c: ClientInfo): string {
  if (c.vendor) return c.vendor;
  if (!c.mac_known) return "";
  if (c.vendor_unknown_reason === "randomized") return "private MAC";
  return "unknown vendor";
}

export default function FilterBar({ filters, onChange, clients, autoRefresh, onToggleAutoRefresh, csvHref }: Props) {
  const [vendorSearch, setVendorSearch] = useState("");

  const visibleClients = useMemo(() => {
    const q = vendorSearch.trim().toLowerCase();
    if (!q) return clients;
    return clients.filter((c) => vendorLabel(c).toLowerCase().includes(q));
  }, [clients, vendorSearch]);

  // The currently selected client stays choosable even if a vendor search
  // narrows it out of view, so the filter bar never silently drops an
  // already-active dashboard-wide selection.
  const selectedClient = clients.find((c) => c.ip === filters.client);
  const options =
    selectedClient && !visibleClients.includes(selectedClient)
      ? [selectedClient, ...visibleClients]
      : visibleClients;

  return (
    <div className="filter-bar">
      <input
        type="text"
        placeholder="Search vendor…"
        value={vendorSearch}
        onChange={(e) => setVendorSearch(e.target.value)}
        title="Narrow the client list below by vendor (e.g. &quot;Espressif&quot;)"
      />

      <select
        value={filters.client}
        onChange={(e) => onChange({ ...filters, client: e.target.value })}
      >
        <option value="">All clients</option>
        {options.map((c) => (
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

      <a className="btn-link" href={csvHref} download>
        Export CSV
      </a>

      <button className={autoRefresh ? "active" : ""} onClick={onToggleAutoRefresh}>
        {autoRefresh ? "● Live" : "Paused"}
      </button>
    </div>
  );
}
