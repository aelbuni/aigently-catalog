import type { StackConfig } from "@aigently/mvp-catalog";
import type { KevEntry } from "./cisa-kev";
import type { AffectedProduct, NormalisedThreat } from "../types";
import { mapCwesToOwasp, normaliseSeverity } from "../normalise";

const NPM_AUDIT_URL = "https://registry.npmjs.org/-/npm/v1/security/audits/quick";

interface NpmAdvisory {
  id: number;
  title: string;
  severity: string;
  overview?: string;
  cwe?: string[];
  cves?: string[];
  url?: string;
  module_name: string;
  vulnerable_versions?: string;
  patched_versions?: string;
}

export async function fetchNpmAdvisories(
  packages: Record<string, string>
): Promise<NpmAdvisory[]> {
  const payload = {
    name: "aigently-scan",
    version: "1.0.0",
    requires:     packages,
    dependencies: Object.fromEntries(
      Object.entries(packages).map(([k, v]) => [k, { version: v }])
    ),
  };

  const res = await fetch(NPM_AUDIT_URL, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(payload),
  });

  if (!res.ok) throw new Error(`npm audit failed: ${res.status}`);
  const data = await res.json() as { advisories?: Record<string, NpmAdvisory> };
  return Object.values(data.advisories ?? {});
}

export function normaliseNpmAdvisory(
  adv:       NpmAdvisory,
  stackSlug: string,
  config:    StackConfig,
  kevMap:    Map<string, KevEntry>
): NormalisedThreat | null {
  const sev = normaliseSeverity("npm", adv.severity);
  if (sev === "low" || sev === "info") return null;

  const cwes = (adv.cwe ?? []) as string[];
  const relevantCwes = cwes.filter(c => config.cwePriority.includes(c));
  const cveId  = adv.cves?.[0] ?? null;

  if (relevantCwes.length === 0 && !cveId) return null;
  if (!adv.url && !cveId) return null;

  const externalId = `npm-${adv.id}`;
  const publicId   = cveId ?? `GHSA-npm-${adv.id}`;
  const kevEntry   = cveId ? kevMap.get(cveId) : undefined;

  const affected: AffectedProduct[] = [{
    name:                   adv.module_name,
    ecosystem:              "npm",
    vulnerableVersionRange: adv.vulnerable_versions ?? null,
    patchedVersions:        adv.patched_versions ?? null,
  }];

  return {
    publicId,
    externalId,
    family:              "owasp_web",
    name:                adv.title,
    severity:            sev,
    description:         adv.overview ?? null,
    cveId,
    source:              cveId ? "ghsa" : "osv",
    sourceUrl:           adv.url ?? null,
    publishedAt:         null,
    owaspRefs:           mapCwesToOwasp(cwes),
    mitreAttackIds:      [],
    affectedProducts:    affected,
    patchedVersion:      adv.patched_versions ?? null,
    isActivelyExploited: !!kevEntry,
    cisaActionDue:       kevEntry?.dueDate ?? null,
    details:             { rawAdvisory: adv },
    affectedStackSlugs:  [stackSlug],
  };
}
