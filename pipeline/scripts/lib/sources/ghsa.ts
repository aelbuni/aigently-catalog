import type { StackConfig } from "@aigently/mvp-catalog";
import type { KevEntry } from "./cisa-kev";
import type { AffectedProduct, NormalisedThreat } from "../types";
import { mapCwesToOwasp, normaliseSeverity } from "../normalise";

const GHSA_BASE  = "https://api.github.com/advisories";
const MAX_PAGES  = 20;

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

interface GhsaAdvisory {
  ghsa_id: string;
  cve_id?: string | null;
  summary: string;
  description?: string;
  severity: string;
  published_at?: string;
  html_url?: string;
  cwes?: Array<{ cwe_id: string }>;
  vulnerabilities?: Array<{
    package: { name: string; ecosystem: string };
    vulnerable_version_range?: string;
    first_patched_version?: string;
  }>;
}

export async function fetchGhsaForEcosystem(
  ecosystem: string,
  token?:    string
): Promise<GhsaAdvisory[]> {
  const headers: Record<string, string> = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const since = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
  const results: GhsaAdvisory[] = [];
  let page = 1;

  while (true) {
    const url =
      `${GHSA_BASE}?ecosystem=${ecosystem}&severity=critical,high` +
      `&per_page=100&page=${page}&updated_after=${since}`;

    const res = await fetch(url, { headers });
    if (!res.ok) break;

    const batch = await res.json() as GhsaAdvisory[];
    if (batch.length === 0) break;

    results.push(...batch);
    if (page >= MAX_PAGES) break;
    page++;
    await sleep(200);
  }

  return results;
}

export function normaliseGhsa(
  adv:       GhsaAdvisory,
  stackSlug: string,
  config:    StackConfig,
  kevMap:    Map<string, KevEntry>
): NormalisedThreat | null {
  const sev = normaliseSeverity("ghsa", adv.severity);
  if (sev === "low" || sev === "info") return null;

  const cwes = adv.cwes?.map(c => c.cwe_id) ?? [];
  const relevantCwes = cwes.filter(c => config.cwePriority.includes(c));
  const cveId = adv.cve_id ?? null;

  if (relevantCwes.length === 0 && !cveId) return null;
  if (!adv.html_url && !cveId) return null;

  const externalId = adv.ghsa_id;
  const publicId   = cveId ?? adv.ghsa_id;
  const kevEntry   = cveId ? kevMap.get(cveId) : undefined;

  const affected: AffectedProduct[] = (adv.vulnerabilities ?? []).map(v => ({
    name:                   v.package.name,
    ecosystem:              v.package.ecosystem,
    vulnerableVersionRange: v.vulnerable_version_range ?? null,
    patchedVersions:        v.first_patched_version ?? null,
  }));

  return {
    publicId,
    externalId,
    family:              "owasp_web",
    name:                adv.summary,
    severity:            sev,
    description:         adv.description ?? null,
    cveId,
    source:              "ghsa",
    sourceUrl:           adv.html_url ?? null,
    publishedAt:         adv.published_at ? new Date(adv.published_at) : null,
    owaspRefs:           mapCwesToOwasp(cwes),
    mitreAttackIds:      [],
    affectedProducts:    affected,
    patchedVersion:      affected[0]?.patchedVersions ?? null,
    isActivelyExploited: !!kevEntry,
    cisaActionDue:       kevEntry?.dueDate ?? null,
    details:             { rawGhsa: adv },
    affectedStackSlugs:  [stackSlug],
  };
}
