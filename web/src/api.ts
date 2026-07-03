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
};
