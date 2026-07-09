export interface QueryRow {
  timestamp: number;
  domain: string;
  query_type: string;
  raw_status: number;
  status: "allowed" | "blocked" | "unknown";
  client_ip: string;
  client_name: string;
}

export interface QueriesResponse {
  total: number;
  limit: number;
  offset: number;
  rows: QueryRow[];
}

// /api/tail returns the same row shape as /api/queries, plus `id` — needed
// as the second half of the compound (timestamp, id) polling cursor, since
// real Pi-hole timestamps are floats and can collide across rows.
export interface TailRow extends QueryRow {
  id: number;
}

export interface ClientInfo {
  ip: string;
  name: string;
  query_count: number;
  // Vendor enrichment (#4/#5) — see DeviceNameRow for field semantics. Lets
  // the client picker be searched/filtered by vendor (#11).
  hwaddr: string | null;
  mac_known: boolean;
  vendor: string | null;
  vendor_unknown_reason: "randomized" | "unlisted" | null;
}

export interface Summary {
  total_queries: number;
  blocked: number;
  blocked_pct: number;
  unique_clients: number;
  unique_domains: number;
}

export interface TopEntry {
  domain?: string;
  ip?: string;
  name?: string;
  count: number;
}

export interface ClientActivity {
  ip: string;
  name: string;
  count: number;
  first_seen: number | null;
  last_seen: number | null;
  sparkline: number[];
}

export interface QueryTypeEntry {
  type_code: number;
  type: string;
  count: number;
}

export interface TimeseriesPoint {
  t: number;
  allowed: number;
  blocked: number;
  total: number;
}

export interface Timeseries {
  since: number;
  until: number;
  bucket_seconds: number;
  series: TimeseriesPoint[];
}

export interface HeatmapResult {
  tz: string;
  days: number;
  // grid[weekday][hour] — weekday follows Python's datetime.weekday(): Monday=0, Sunday=6.
  grid: number[][];
  max: number;
}

export interface SimulationClientImpact {
  ip: string;
  name: string;
  matched_count: number;
  total_count: number;
  pct_of_client_traffic: number;
}

export interface SimulationResult {
  pattern: string;
  since: number;
  total_matches: number;
  unique_domains: number;
  top_domains: { domain: string; count: number }[];
  clients: SimulationClientImpact[];
}

export type RuleType =
  | "volume_threshold"
  | "new_device"
  | "domain_keyword"
  | "device_quiet"
  | "new_vendor"
  | "digest";

export interface AlertRule {
  id: number;
  name: string;
  type: RuleType;
  enabled: boolean;
  params: Record<string, unknown>;
  created_at: number;
}

export interface AlertEvent {
  id: number;
  rule_id: number | null;
  rule_name: string;
  type: RuleType;
  severity: "info" | "warning" | "critical";
  message: string;
  created_at: number;
}

export interface AlertsResponse {
  evaluated_at: number;
  new: number;
  events: AlertEvent[];
}

export interface ClientDetail {
  ip: string;
  name: string;
  first_seen: number | null;
  last_seen: number | null;
  summary: Summary;
  top_domains: TopEntry[];
  query_types: QueryTypeEntry[];
  timeseries: Timeseries;
  // Vendor enrichment (#4/#5). hwaddr/vendor are null and mac_known is false
  // when DNS Watch never observed a real MAC for this client (Pi-hole's own
  // "ip-<addr>" placeholder, or no `network` table data at all). When
  // mac_known is true but vendor is null, vendor_unknown_reason explains why:
  // "randomized" (locally-administered/private MAC, no vendor by design) or
  // "unlisted" (real MAC, genuinely not in our offline OUI table).
  hwaddr: string | null;
  mac_known: boolean;
  vendor: string | null;
  vendor_unknown_reason: "randomized" | "unlisted" | null;
}

export interface Anomaly {
  ip: string;
  name: string;
  kind: "silent" | "spike";
  baseline_avg: number;
  baseline_stddev: number;
  current_value: number;
  window_since: number;
  window_until: number;
  // Only set for kind "silent" (#6/#7) — the same presence qualifier a
  // device_quiet alert rule would attach for this client, so the Alerts and
  // Anomalies panels never disagree about the same client going quiet.
  presence_note?: string;
}

export type WebhookFormat = "generic" | "slack" | "discord";

export interface AppSettings {
  webhook_enabled: boolean;
  webhook_url: string;
  webhook_format: WebhookFormat;
  // The server never returns the real secret (it's a bearer credential for an
  // external service) — only whether one is currently configured.
  webhook_secret_set: boolean;
}

export interface AppSettingsUpdate {
  webhook_enabled?: boolean;
  webhook_url?: string;
  webhook_format?: WebhookFormat;
  // Omit entirely to leave the saved secret untouched; send "" to clear it.
  webhook_secret?: string;
}

export interface DeviceNameRow {
  ip: string;
  // The user's own override, if set — takes priority everywhere else in the
  // app over pihole_name/resolved_name (see server/app/db.py _display_name).
  manual_name: string | null;
  // Pi-hole's own name (DHCP lease / mDNS / set in Pi-hole's own UI), if any.
  pihole_name: string | null;
  // DNS Watch's own reverse-DNS (PTR) cache, if any — see resolve.py.
  resolved_name: string | null;
  // What the rest of the dashboard currently shows for this ip.
  display_name: string;
  query_count: number;
  last_seen: number | null;
  // False for a manual name whose ip has no CURRENT Pi-hole traffic (a
  // device that's gone quiet or been replaced) — kept visible so a stale
  // override stays deletable instead of silently vanishing.
  seen: boolean;
  hwaddr: string | null;
  mac_known: boolean;
  vendor: string | null;
  vendor_unknown_reason: "randomized" | "unlisted" | null;
}

export interface Filters {
  client: string; // "" = all
  domain: string;
  status: string; // all | allowed | blocked
  range: string; // 15m | 1h | 24h | 7d
}

function qs(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : "";
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json() as Promise<T>;
}

async function sendJson<T>(url: string, method: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    // FastAPI's HTTPException body is {"detail": "..."} — surface that
    // instead of a bare status code when the server bothered to explain
    // itself (e.g. a validation message on a 400).
    const detail = await res
      .json()
      .then((b) => (typeof b?.detail === "string" ? b.detail : null))
      .catch(() => null);
    throw new Error(detail || `${method} ${url} -> ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => getJson<{ ok: boolean; error?: string }>("/api/health"),

  clients: () => getJson<ClientInfo[]>("/api/clients"),

  queries: (f: Filters, limit = 200, offset = 0) =>
    getJson<QueriesResponse>(
      `/api/queries${qs({
        client: f.client,
        domain: f.domain,
        status: f.status,
        range: f.range,
        limit,
        offset,
      })}`
    ),

  summary: (f: Pick<Filters, "client" | "range">) =>
    getJson<Summary>(`/api/summary${qs({ client: f.client, range: f.range })}`),

  topDomains: (f: Pick<Filters, "client" | "range">) =>
    getJson<TopEntry[]>(`/api/top-domains${qs({ client: f.client, range: f.range })}`),

  topClients: (f: Pick<Filters, "range">) =>
    getJson<TopEntry[]>(`/api/top-clients${qs({ range: f.range })}`),

  clientActivity: (f: Pick<Filters, "range">, limit = 10, buckets = 20) =>
    getJson<ClientActivity[]>(
      `/api/client-activity${qs({ range: f.range, limit, buckets })}`
    ),

  clientDetail: (ip: string, range: string) =>
    getJson<ClientDetail>(`/api/client/${encodeURIComponent(ip)}${qs({ range })}`),

  queryTypes: (f: Pick<Filters, "client" | "range">) =>
    getJson<QueryTypeEntry[]>(`/api/query-types${qs({ client: f.client, range: f.range })}`),

  timeseries: (f: Pick<Filters, "client" | "range">, buckets = 60) =>
    getJson<Timeseries>(`/api/timeseries${qs({ client: f.client, range: f.range, buckets })}`),

  // Returns the download URL for the current filter view (browser handles the download).
  csvUrl: (f: Filters) =>
    `/api/queries.csv${qs({ client: f.client, domain: f.domain, status: f.status, range: f.range })}`,

  anomalies: () => getJson<Anomaly[]>("/api/anomalies"),

  // Underlying query events behind a single anomaly: this client, scoped to
  // the exact baseline-deviation window the anomaly was computed over.
  // Reuses /api/queries — `since`/`until` bypass the `range` preset entirely.
  anomalyQueries: (ip: string, since: number, until: number, limit = 200) =>
    getJson<QueriesResponse>(
      `/api/queries${qs({ client: ip, since, until, limit })}`
    ),

  tail: (since: number, sinceId: number, limit = 500) =>
    getJson<TailRow[]>(`/api/tail${qs({ since, since_id: sinceId, limit })}`),

  simulateBlocklist: (pattern: string) =>
    sendJson<SimulationResult>("/api/simulate-blocklist", "POST", { pattern, range: "7d" }),

  clientHeatmap: (ip: string, days = 7) =>
    getJson<HeatmapResult>(
      `/api/client/${encodeURIComponent(ip)}/heatmap${qs({
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        days,
      })}`
    ),

  clientHeatmapCell: (ip: string, weekday: number, hour: number, days = 7) =>
    getJson<QueryRow[]>(
      `/api/client/${encodeURIComponent(ip)}/heatmap/cell${qs({
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        weekday,
        hour,
        days,
      })}`
    ),

  alerts: (limit = 50) => getJson<AlertsResponse>(`/api/alerts${qs({ limit })}`),
  listRules: () => getJson<AlertRule[]>("/api/alert-rules"),
  createRule: (r: { name: string; type: RuleType; params: Record<string, unknown>; enabled?: boolean }) =>
    sendJson<AlertRule>("/api/alert-rules", "POST", r),
  updateRule: (id: number, patch: { name?: string; enabled?: boolean; params?: Record<string, unknown> }) =>
    sendJson<AlertRule>(`/api/alert-rules/${id}`, "PATCH", patch),
  deleteRule: (id: number) => sendJson<{ deleted: number }>(`/api/alert-rules/${id}`, "DELETE"),

  deviceNames: () => getJson<DeviceNameRow[]>("/api/device-names"),
  setDeviceName: (ip: string, name: string) =>
    sendJson<{ ip: string; name: string }>(`/api/device-names/${encodeURIComponent(ip)}`, "PUT", { name }),
  deleteDeviceName: (ip: string) =>
    sendJson<{ deleted: string }>(`/api/device-names/${encodeURIComponent(ip)}`, "DELETE"),

  getSettings: () => getJson<AppSettings>("/api/settings"),
  updateSettings: (patch: AppSettingsUpdate) =>
    sendJson<AppSettings>("/api/settings", "PATCH", patch),
  testWebhook: (url: string, secret: string, format: WebhookFormat) =>
    sendJson<{ ok: boolean; error: string | null }>("/api/settings/test-webhook", "POST", {
      url,
      secret,
      format,
    }),
};
