import type { NormalisedThreat } from "./types";

export const CWE_TO_OWASP_WEB: Record<string, string> = {
  // A01 — Broken Access Control
  "CWE-284": "A01", "CWE-285": "A01", "CWE-639": "A01",
  "CWE-863": "A01", "CWE-22":  "A01", "CWE-59":  "A01",
  // A02 — Cryptographic Failures
  "CWE-327": "A02", "CWE-326": "A02", "CWE-312": "A02",
  "CWE-311": "A02", "CWE-330": "A02", "CWE-295": "A02",
  // A03 — Injection
  "CWE-89":   "A03", "CWE-79":   "A03", "CWE-78":  "A03",
  "CWE-94":   "A03", "CWE-20":   "A03", "CWE-1321":"A03",
  "CWE-77":   "A03", "CWE-917":  "A03", "CWE-74":  "A03",
  // A04 — Insecure Design
  "CWE-915":  "A04", "CWE-434": "A04", "CWE-840": "A04",
  // A05 — Security Misconfiguration
  "CWE-116":  "A05", "CWE-942": "A05",
  "CWE-346":  "A05", "CWE-732": "A05", "CWE-16":  "A05",
  // A06 — Vulnerable and Outdated Components
  "CWE-400":  "A06", "CWE-1104":"A06", "CWE-1035":"A06",
  // A07 — Identification and Authentication Failures
  "CWE-287":  "A07", "CWE-306": "A07", "CWE-307": "A07",
  "CWE-521":  "A07",
  // A05 + A07 overlap — hardcoded credentials
  "CWE-798":  "A05",
  // A08 — Software and Data Integrity Failures / CSRF
  "CWE-502":  "A08", "CWE-352": "A08", "CWE-349": "A08",
  "CWE-494":  "A08",
  // A09 — Security Logging and Monitoring Failures
  "CWE-532":  "A09", "CWE-778": "A09",
  // A10 — SSRF
  "CWE-918":  "A10",
};

export const CWE_TO_OWASP_LLM: Record<string, string> = {
  "CWE-20":   "LLM01",
  "CWE-200":  "LLM02",
  "CWE-1104": "LLM03",
  "CWE-506":  "LLM04",
  "CWE-116":  "LLM05",
  "CWE-284":  "LLM06",
  "CWE-285":  "LLM06",
  "CWE-312":  "LLM07",
  "CWE-400":  "LLM10",
};

export function mapCwesToOwasp(cwes: string[]): string[] {
  const refs = new Set<string>();
  for (const cwe of cwes) {
    const webRef = CWE_TO_OWASP_WEB[cwe];
    const llmRef = CWE_TO_OWASP_LLM[cwe];
    if (webRef) refs.add(webRef);
    if (llmRef) refs.add(llmRef);
  }
  return [...refs].sort();
}

export function normaliseSeverity(
  _source: string,
  rawSeverity?: string | number,
  cvssScore?: number
): "critical" | "high" | "medium" | "low" | "info" {
  if (cvssScore !== undefined) {
    if (cvssScore >= 9.0) return "critical";
    if (cvssScore >= 7.0) return "high";
    if (cvssScore >= 4.0) return "medium";
    if (cvssScore >= 0.1) return "low";
    return "info";
  }

  const s = String(rawSeverity ?? "").toLowerCase();
  if (s === "critical")  return "critical";
  if (s === "high")      return "high";
  if (s === "moderate")  return "medium";
  if (s === "medium")    return "medium";
  if (s === "low")       return "low";
  return "info";
}

const SOURCE_PRIORITY: Record<string, number> = {
  ghsa: 3, osv: 2, nvd: 2, cisa_kev: 1, aigently: 5, mitre_atlas: 4,
};

export function deduplicateThreats(threats: NormalisedThreat[]): NormalisedThreat[] {
  const byCveId  = new Map<string, NormalisedThreat>();
  const byExtId  = new Map<string, NormalisedThreat>();

  for (const t of threats) {
    if (t.cveId) {
      const existing = byCveId.get(t.cveId);
      if (existing) {
        existing.affectedStackSlugs = [
          ...new Set([...existing.affectedStackSlugs, ...t.affectedStackSlugs]),
        ];
        if ((SOURCE_PRIORITY[t.source] ?? 0) > (SOURCE_PRIORITY[existing.source] ?? 0)) {
          const slugs = existing.affectedStackSlugs;
          Object.assign(existing, t);
          existing.affectedStackSlugs = slugs;
        }
        continue;
      }
      byCveId.set(t.cveId, t);
    }

    if (!byExtId.has(t.externalId)) {
      byExtId.set(t.externalId, t);
    }
  }

  return [
    ...byCveId.values(),
    ...[...byExtId.values()].filter(t => !t.cveId),
  ];
}
