import { useMemo, useState } from "react";
import { ClientInfo, Filters, Tag, Vendor } from "../api";

interface Props {
  filters: Filters;
  onChange: (f: Filters) => void;
  clients: ClientInfo[];
  tags: Tag[];
  vendors: Vendor[];
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
  vendors,
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

  // A single dropdown covers all three scopes (#11/#31) -- "tag:<name>",
  // "vendor:<name>", or "ip:<ip>" -- rather than separate selects that would
  // need their own mutual-exclusion bookkeeping. filters.client/tag/vendor
  // are still the plain values the rest of the app (and the API layer) reads.
  const selectValue = filters.tag
    ? `tag:${filters.tag}`
    : filters.vendor
      ? `vendor:${filters.vendor}`
      : filters.client
        ? `ip:${filters.client}`
        : "";
  function handleScopeChange(value: string) {
    if (value.startsWith("tag:")) {
      onChange({ ...filters, tag: value.slice(4), vendor: "", client: "" });
    } else if (value.startsWith("vendor:")) {
      onChange({ ...filters, vendor: value.slice(7), tag: "", client: "" });
    } else if (value.startsWith("ip:")) {
      onChange({ ...filters, client: value.slice(3), tag: "", vendor: "" });
    } else {
      onChange({ ...filters, client: "", tag: "", vendor: "" });
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
        {vendors.length > 0 && (
          <optgroup label="Vendors">
            {vendors.map((v) => (
              <option key={`vendor:${v.name}`} value={`vendor:${v.name}`}>
                {v.name} ({v.ips.length})
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
