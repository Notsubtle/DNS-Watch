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

  queryTypes: (f: Pick<Filters, "client" | "range">) =>
    getJson<QueryTypeEntry[]>(`/api/query-types${qs({ client: f.client, range: f.range })}`),

  timeseries: (f: Pick<Filters, "client" | "range">, buckets = 60) =>
    getJson<Timeseries>(`/api/timeseries${qs({ client: f.client, range: f.range, buckets })}`),

  // Returns the download URL for the current filter view (browser handles the download).
  csvUrl: (f: Filters) =>
    `/api/queries.csv${qs({ client: f.client, domain: f.domain, status: f.status, range: f.range })}`,
};
