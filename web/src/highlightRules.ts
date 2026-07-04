// Highlight rules for the Live Stream console — deliberately client-only,
// no backend involvement. Unlike Feature 3's blocklist simulator (real
// regex, for precisely defining a block rule), these are glob-style
// (`*netflix*`) — the friendlier syntax for "highlight while I watch."

export interface HighlightRule {
  id: string;
  pattern: string; // glob, e.g. "*netflix*"
  color: string; // hex, from a native color input
  field: "domain" | "client";
}

const STORAGE_KEY = "dnswatch.highlightRules";

export function loadHighlightRules(): HighlightRule[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    // localStorage blocked (some private-browsing modes) or corrupt JSON —
    // fail to "no highlight rules" rather than break the console.
    return [];
  }
}

export function saveHighlightRules(rules: HighlightRule[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
  } catch {
    // Rule just won't survive a reload; nothing else to do here.
  }
}

// Converts a simple glob into an anchored, case-insensitive RegExp. Only `*`
// is special (-> .*); every other character is escaped literally, so a
// pathological regex isn't reachable from this subset — but the compile step
// is still wrapped defensively (skip the rule, don't crash the console)
// rather than assumed to always succeed.
export function compileGlob(pattern: string): RegExp | null {
  try {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    return new RegExp(`^${escaped}$`, "i");
  } catch {
    return null;
  }
}

export interface CompiledRule {
  rule: HighlightRule;
  regex: RegExp;
}

export function compileRules(rules: HighlightRule[]): CompiledRule[] {
  const compiled: CompiledRule[] = [];
  for (const rule of rules) {
    const regex = compileGlob(rule.pattern);
    if (regex) compiled.push({ rule, regex });
  }
  return compiled;
}

// First match wins (list order) — a deterministic choice when more than one
// rule matches the same row, rather than an undefined "last write wins" from
// render/iteration order.
export function matchHighlightColor(
  compiled: CompiledRule[],
  domain: string,
  clientName: string,
  clientIp: string
): string | null {
  for (const { rule, regex } of compiled) {
    const target = rule.field === "domain" ? domain : `${clientName} ${clientIp}`;
    if (regex.test(target)) return rule.color;
  }
  return null;
}
