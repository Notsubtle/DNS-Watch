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

export interface ClientInfo {
  ip: string;
  name: string;
  query_count: number;
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

export type RuleType = "volume_threshold" | "new_device" | "domain_keyword" | "device_quiet";

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
}

export type WebhookFormat = "generic" | "slack" | "discord";

export interface AppSettings {
  webhook_enabled: boolean;
  webhook_url: string;
  webhook_secret: string;
  webhook_format: WebhookFormat;
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
  if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}`);
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

  alerts: (limit = 50) => getJson<AlertsResponse>(`/api/alerts${qs({ limit })}`),
  listRules: () => getJson<AlertRule[]>("/api/alert-rules"),
  createRule: (r: { name: string; type: RuleType; params: Record<string, unknown>; enabled?: boolean }) =>
    sendJson<AlertRule>("/api/alert-rules", "POST", r),
  updateRule: (id: number, patch: { name?: string; enabled?: boolean; params?: Record<string, unknown> }) =>
    sendJson<AlertRule>(`/api/alert-rules/${id}`, "PATCH", patch),
  deleteRule: (id: number) => sendJson<{ deleted: number }>(`/api/alert-rules/${id}`, "DELETE"),

  getSettings: () => getJson<AppSettings>("/api/settings"),
  updateSettings: (patch: Partial<AppSettings>) =>
    sendJson<AppSettings>("/api/settings", "PATCH", patch),
  testWebhook: (url: string, secret: string, format: WebhookFormat) =>
    sendJson<{ ok: boolean; error: string | null }>("/api/settings/test-webhook", "POST", {
      url,
      secret,
      format,
    }),
};
