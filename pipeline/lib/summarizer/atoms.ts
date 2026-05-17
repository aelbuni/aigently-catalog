export type DirectiveAtom = {
  content: string;
  sourceRuleId: string;
  layerSlug: string;
  severity: "critical" | "high" | "medium" | "low";
  cweRefs: string[];
  conflictResolution?: "kept" | "merged" | "conflict_resolved" | "deduplicated";
};

const DIRECTIVE_RE = /^[-*]\s+(DO NOT|NEVER|AVOID|ALWAYS|ENSURE|REQUIRE|WHEN|IF)\b.+/im;
const CWE_RE = /CWE-\d+/gi;
const SEVERITY_SIGNALS: Record<string, DirectiveAtom["severity"]> = {
  critical: "critical",
  inject: "high",
  xss: "high",
  csrf: "high",
  rce: "critical",
  sqli: "critical",
  auth: "high",
  session: "high",
  secret: "high",
  pii: "high",
  privesc: "critical",
  medium: "medium",
  low: "low",
};

function inferSeverity(line: string): DirectiveAtom["severity"] {
  const lower = line.toLowerCase();
  for (const [kw, sev] of Object.entries(SEVERITY_SIGNALS)) {
    if (lower.includes(kw)) return sev;
  }
  return "medium";
}

/** Split rule body into directive atoms (DO / DON'T / WHEN-THEN lines). */
export function parseRuleIntoAtoms(
  bodyMdx: string,
  ruleId: string,
  layerSlug: string
): DirectiveAtom[] {
  const lines = bodyMdx.split("\n").map((l) => l.trim()).filter(Boolean);
  const atoms: DirectiveAtom[] = [];
  for (const line of lines) {
    if (!DIRECTIVE_RE.test(line) && line.length < 20) continue;
    if (line.startsWith("#") || line.startsWith("<!--")) continue;
    const cweRefs = [...line.matchAll(CWE_RE)].map((m) => m[0]);
    atoms.push({
      content: line,
      sourceRuleId: ruleId,
      layerSlug,
      severity: inferSeverity(line),
      cweRefs,
    });
  }
  return atoms;
}
