import { useMemo, useState } from "react";
import { ClientInfo, Filters, Tag } from "../api";

interface Props {
  filters: Filters;
  onChange: (f: Filters) => void;
  clients: ClientInfo[];
  tags: Tag[];
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

export default function FilterBar({
  filters,
  onChange,
  clients,
  tags,
  autoRefresh,
  onToggleAutoRefresh,
  csvHref,
}: Props) {
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

  // A single dropdown covers both scopes (#31) -- "tag:<name>" or "ip:<ip>" --
  // rather than two separate selects that would need their own mutual-
  // exclusion bookkeeping. filters.client/filters.tag are still the plain
  // values the rest of the app (and the API layer) reads.
  const selectValue = filters.tag ? `tag:${filters.tag}` : filters.client ? `ip:${filters.client}` : "";
  function handleScopeChange(value: string) {
    if (value.startsWith("tag:")) {
      onChange({ ...filters, tag: value.slice(4), client: "" });
    } else if (value.startsWith("ip:")) {
      onChange({ ...filters, client: value.slice(3), tag: "" });
    } else {
      onChange({ ...filters, client: "", tag: "" });
    }
  }

  return (
    <div className="filter-bar">
      <input
        type="text"
        placeholder="Search vendor…"
        value={vendorSearch}
        onChange={(e) => setVendorSearch(e.target.value)}
        title="Narrow the device list below by vendor (e.g. &quot;Espressif&quot;)"
      />

      <select value={selectValue} onChange={(e) => handleScopeChange(e.target.value)}>
        <option value="">All clients</option>
        {tags.length > 0 && (
          <optgroup label="Tags">
            {tags.map((t) => (
              <option key={`tag:${t.name}`} value={`tag:${t.name}`}>
                🏷 {t.name} ({t.ips.length})
              </option>
            ))}
          </optgroup>
        )}
        <optgroup label="Devices">
          {options.map((c) => (
            <option key={c.ip} value={`ip:${c.ip}`}>
              {c.name} ({c.query_count})
            </option>
          ))}
        </optgroup>
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
