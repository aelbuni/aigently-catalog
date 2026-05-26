const KEYWORD_MAP: Record<string, string[]> = {
  auth:            ["auth_session", "authz_access"],
  jwt:             ["auth_session"],
  session:         ["auth_session"],
  login:           ["auth_session"],
  password:        ["auth_session", "secrets_credentials"],
  oauth:           ["auth_session"],
  rbac:            ["authz_access"],
  permission:      ["authz_access"],
  ownership:       ["authz_access"],
  rls:             ["authz_access", "database"],
  sql:             ["input_validation", "database"],
  inject:          ["input_validation"],
  xss:             ["input_validation"],
  sanitiz:         ["input_validation"],
  validation:      ["input_validation"],
  api:             ["api_security", "auth_session"],
  "rate lim":      ["api_security"],
  throttl:         ["api_security"],
  cors:            ["api_security"],
  secret:          ["secrets_credentials"],
  credential:      ["secrets_credentials"],
  "api key":       ["secrets_credentials"],
  env:             ["secrets_credentials", "infrastructure"],
  ".env":          ["secrets_credentials"],
  package:         ["dependency_supply"],
  npm:             ["dependency_supply"],
  dependency:      ["dependency_supply"],
  supply:          ["dependency_supply"],
  pii:             ["data_privacy"],
  gdpr:            ["data_privacy"],
  "personal data": ["data_privacy"],
  logging:         ["observability", "data_privacy"],
  deploy:          ["infrastructure"],
  cicd:            ["infrastructure"],
  s3:              ["infrastructure"],
  iam:             ["infrastructure"],
  supabase:        ["database", "authz_access"],
  postgres:        ["database"],
  database:        ["database"],
  cache:           ["caching_cdn"],
  cdn:             ["caching_cdn"],
  csp:             ["frontend_network"],
  headers:         ["frontend_network"],
  https:           ["frontend_network"],
  llm:             ["ai_safety", "input_validation"],
  prompt:          ["ai_safety"],
  "ai safety":     ["ai_safety"],
  backup:          ["resilience"],
  failover:        ["resilience"],
  recovery:        ["resilience"],
};

/** Infer layer slugs from a natural-language intent string (keyword heuristics, no LLM). */
export function resolveLayersFromIntent(intent: string): string[] {
  const lower = intent.toLowerCase();
  const matched = new Set<string>();

  for (const [kw, layers] of Object.entries(KEYWORD_MAP)) {
    if (lower.includes(kw)) {
      layers.forEach((l) => matched.add(l));
    }
  }

  if (matched.size === 0) {
    return ["auth_session", "input_validation"];
  }

  return [...matched];
}
