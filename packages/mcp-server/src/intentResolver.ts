const DEPS_KEYWORDS = [
  "package", "npm", "dependency", "dependencies", "supply chain",
  "cve", "vulnerability", "upgrade", "patch", "audit", "yarn", "pnpm",
  "pypi", "pip", "requirements", "gemfile", "go.mod",
];

const PATTERNS_KEYWORDS = [
  "auth", "jwt", "session", "login", "password", "oauth", "rbac",
  "permission", "injection", "xss", "sanitiz", "validation", "sql",
  "secret", "credential", "api key", "cors", "csp", "headers",
  "https", "llm", "prompt", "cache", "rls", "ownership",
];

/** Infer rule type from a natural-language intent string (keyword heuristics, no LLM). */
export function resolveRuleTypeFromIntent(intent: string): "all" | "patterns" | "deps" {
  const lower = intent.toLowerCase();
  const wantsDeps     = DEPS_KEYWORDS.some((kw)     => lower.includes(kw));
  const wantsPatterns = PATTERNS_KEYWORDS.some((kw) => lower.includes(kw));

  if (wantsDeps && !wantsPatterns) return "deps";
  if (wantsPatterns && !wantsDeps) return "patterns";
  return "all";
}

/** @deprecated Use resolveRuleTypeFromIntent instead */
export function resolveLayersFromIntent(_intent: string): string[] {
  return [];
}
