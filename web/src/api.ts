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

// Cross-client domain fan-out (#34) — a domain hit by several distinct
// clients within one short window, surfacing synchronized beaconing a
// per-client view can't show.
export interface FanoutClient {
  ip: string;
  name: string;
}

export interface FanoutEntry {
  domain: string;
  window_start: number;
  window_end: number;
  client_count: number;
  query_count: number;
  clients: FanoutClient[];
}

// Domains ranked by average resolution latency (#47) -- Pi-hole's own
// reply_time, surfacing slow/uncached/upstream-forwarded lookups. Empty on
// schemas without a reply_time column at all (see db.slowest_domains).
export interface QueryLatencyEntry {
  domain: string;
  avg_reply_ms: number;
  max_reply_ms: number;
  query_count: number;
}

export type RuleType =
  | "volume_threshold"
  | "new_device"
  | "domain_keyword"
  | "device_quiet"
  | "new_vendor"
  | "doh_provider"
  | "digest"
  | "first_seen_domain"
  | "correlated_new_device_domain";

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
  // dedup_key (#42) identifies this exact recurrence (e.g. one device's
  // new-vendor alert) for snoozing; client_ip/domain (#43) are the
  // structured target -- when present -- for deep-linking into the
  // dashboard/heatmap/fan-out view instead of only rendering `message`.
  dedup_key: string;
  client_ip: string | null;
  domain: string | null;
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

// Config backup/export (#45) — a portable JSON snapshot of everything the
// user manually curated (tags, alert rules, device names, webhook settings
// minus the secret, which the API never exposes in plaintext). Typed as
// unknown on the wire since the frontend never needs to inspect its
// contents — it's just downloaded/uploaded whole.
export type BackupData = Record<string, unknown>;

export interface BackupRestoreSummary {
  tags: number;
  alert_rules: number;
  device_names: number;
  settings_restored: boolean;
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
  tag: string; // "" = no tag filter; mutually exclusive with client/vendor (#31)
  vendor: string; // "" = no vendor filter; mutually exclusive with client/tag (#11)
  domain: string;
  status: string; // all | allowed | blocked
  range: string; // 15m | 1h | 24h | 7d
}

// A client tag/group (#31) — a user-defined label applied to a set of IPs,
// so the dashboard filter and alert rules can scope to "all of these
// devices" instead of one IP or every IP.
export interface Tag {
  id: number;
  name: string;
  created_at: number;
  ips: string[];
}

// A distinct resolved vendor (#11 remaining scope) and its current member
// IPs — read-only/derived, unlike Tag: there's nothing to create or delete,
// it just reflects whatever clients currently resolve to that vendor.
export interface Vendor {
  name: string;
  ips: string[];
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
        tag: f.tag,
        vendor: f.vendor,
        domain: f.domain,
        status: f.status,
        range: f.range,
        limit,
        offset,
      })}`
    ),

  summary: (f: Pick<Filters, "client" | "tag" | "vendor" | "range">) =>
    getJson<Summary>(
      `/api/summary${qs({ client: f.client, tag: f.tag, vendor: f.vendor, range: f.range })}`
    ),

  topDomains: (f: Pick<Filters, "client" | "tag" | "vendor" | "range">) =>
    getJson<TopEntry[]>(
      `/api/top-domains${qs({ client: f.client, tag: f.tag, vendor: f.vendor, range: f.range })}`
    ),

  topClients: (f: Pick<Filters, "range">) =>
    getJson<TopEntry[]>(`/api/top-clients${qs({ range: f.range })}`),

  clientActivity: (f: Pick<Filters, "range">, limit = 10, buckets = 20) =>
    getJson<ClientActivity[]>(
      `/api/client-activity${qs({ range: f.range, limit, buckets })}`
    ),

  clientDetail: (ip: string, range: string) =>
    getJson<ClientDetail>(`/api/client/${encodeURIComponent(ip)}${qs({ range })}`),

  queryTypes: (f: Pick<Filters, "client" | "tag" | "vendor" | "range">) =>
    getJson<QueryTypeEntry[]>(
      `/api/query-types${qs({ client: f.client, tag: f.tag, vendor: f.vendor, range: f.range })}`
    ),

  timeseries: (f: Pick<Filters, "client" | "tag" | "vendor" | "range">, buckets = 60) =>
    getJson<Timeseries>(
      `/api/timeseries${qs({
        client: f.client,
        tag: f.tag,
        vendor: f.vendor,
        range: f.range,
        buckets,
      })}`
    ),

  // Returns the download URL for the current filter view (browser handles the download).
  csvUrl: (f: Filters) =>
    `/api/queries.csv${qs({
      client: f.client,
      tag: f.tag,
      vendor: f.vendor,
      domain: f.domain,
      status: f.status,
      range: f.range,
    })}`,

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

  domainFanout: (range: string, bucketMinutes: number, minClients: number) =>
    getJson<FanoutEntry[]>(
      `/api/domain-fanout${qs({ range, bucket_minutes: bucketMinutes, min_clients: minClients })}`
    ),

  queryLatency: (range: string) =>
    getJson<QueryLatencyEntry[]>(`/api/query-latency${qs({ range })}`),

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
  snoozeEvent: (id: number, until: number) =>
    sendJson<{ dedup_key: string; snoozed_until: number }>(
      `/api/alert-events/${id}/snooze`,
      "POST",
      { until }
    ),
  unsnooze: (dedupKey: string) =>
    sendJson<{ unsnoozed: string }>(
      `/api/alert-snoozes/${encodeURIComponent(dedupKey)}`,
      "DELETE"
    ),
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

  listVendors: () => getJson<Vendor[]>("/api/vendors"),

  listTags: () => getJson<Tag[]>("/api/tags"),
  createTag: (name: string) => sendJson<Tag>("/api/tags", "POST", { name }),
  deleteTag: (id: number) => sendJson<{ deleted: number }>(`/api/tags/${id}`, "DELETE"),
  addTagMember: (id: number, ip: string) =>
    sendJson<{ tag_id: number; ip: string }>(`/api/tags/${id}/members`, "POST", { ip }),
  removeTagMember: (id: number, ip: string) =>
    sendJson<{ tag_id: number; removed: string }>(
      `/api/tags/${id}/members/${encodeURIComponent(ip)}`,
      "DELETE"
    ),

  getSettings: () => getJson<AppSettings>("/api/settings"),
  updateSettings: (patch: AppSettingsUpdate) =>
    sendJson<AppSettings>("/api/settings", "PATCH", patch),
  testWebhook: (url: string, secret: string, format: WebhookFormat) =>
    sendJson<{ ok: boolean; error: string | null }>("/api/settings/test-webhook", "POST", {
      url,
      secret,
      format,
    }),

  backupUrl: "/api/backup",
  restoreBackup: (data: BackupData) =>
    sendJson<BackupRestoreSummary>("/api/backup/restore", "POST", data),
};
