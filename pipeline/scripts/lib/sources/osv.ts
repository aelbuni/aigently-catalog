import type { StackConfig } from "@aigently/mvp-catalog";
import type { KevEntry } from "./cisa-kev";
import type { AffectedProduct, NormalisedThreat } from "../types";
import { mapCwesToOwasp, normaliseSeverity } from "../normalise";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}

interface OsvRange {
  events?: OsvEvent[];
}

interface OsvAffected {
  package?: { name: string; ecosystem: string };
  ranges?: OsvRange[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  published?: string;
  aliases?: string[];
  references?: Array<{ url: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: OsvAffected[];
}

export async function fetchOsvForPackage(
  packageName: string,
  ecosystem:   string
): Promise<OsvVuln[]> {
  const res = await fetch(OSV_QUERY_URL, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ package: { name: packageName, ecosystem } }),
  });
  if (!res.ok) throw new Error(`OSV fetch failed for ${packageName}: ${res.status}`);
  const data = await res.json() as { vulns?: OsvVuln[] };
  return data.vulns ?? [];
}

export function normaliseOsvVuln(
  vuln:      OsvVuln,
  stackSlug: string,
  config:    StackConfig,
  kevMap:    Map<string, KevEntry>
): NormalisedThreat | null {
  const rawSev = vuln.database_specific?.severity;
  const sev    = normaliseSeverity("osv", rawSev);
  if (sev === "low" || sev === "info") return null;

  const cwes = (vuln.database_specific?.cwe_ids ?? []) as string[];
  const relevantCwes = cwes.filter(c => config.cwePriority.includes(c));
  const cveId  = vuln.aliases?.find(a => a.startsWith("CVE-")) ?? null;

  if (relevantCwes.length === 0 && !cveId) return null;

  const sourceUrl = vuln.references?.[0]?.url ?? null;
  if (!sourceUrl && !cveId) return null;

  const externalId = vuln.id;
  const publicId   = cveId ?? vuln.id;
  const kevEntry   = cveId ? kevMap.get(cveId) : undefined;

  const affected: AffectedProduct[] = (vuln.affected ?? []).map(a => {
    const events = a.ranges?.[0]?.events ?? [];
    const introduced = events.find(e => e.introduced)?.introduced;
    const fixed      = events.find(e => e.fixed)?.fixed;
    const range      = introduced && fixed
      ? `>=${introduced} <${fixed}`
      : introduced
        ? `>=${introduced}`
        : null;
    return {
      name:                   a.package?.name ?? "",
      ecosystem:              a.package?.ecosystem ?? "",
      vulnerableVersionRange: range,
      patchedVersions:        fixed ?? null,
    };
  });

  return {
    publicId,
    externalId,
    family:              "owasp_web",
    name:                vuln.summary ?? vuln.id,
    severity:            sev,
    description:         vuln.details ?? null,
    cveId,
    source:              "osv",
    sourceUrl,
    publishedAt:         vuln.published ? new Date(vuln.published) : null,
    owaspRefs:           mapCwesToOwasp(cwes),
    mitreAttackIds:      [],
    affectedProducts:    affected,
    patchedVersion:      affected[0]?.patchedVersions ?? null,
    isActivelyExploited: !!kevEntry,
    cisaActionDue:       kevEntry?.dueDate ?? null,
    details:             { rawOsv: vuln },
    affectedStackSlugs:  [stackSlug],
  };
}
