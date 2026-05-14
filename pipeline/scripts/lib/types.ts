import type { InferInsertModel } from "drizzle-orm";
import type { threat, threatStack } from "../../lib/db";

export type ThreatInsert = InferInsertModel<typeof threat>;
export type ThreatStackInsert = InferInsertModel<typeof threatStack>;

export interface AffectedProduct {
  name: string;
  ecosystem: string;
  vulnerableVersionRange: string | null;
  patchedVersions: string | null;
}

export interface NormalisedThreat {
  publicId: string;
  externalId: string;
  family: "owasp_web" | "owasp_llm" | "mitre_atlas" | "vibe_coding";
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string | null;
  cveId: string | null;
  // Must match threatSourceEnum — "npm-audit" is NOT a valid value
  source: "nvd" | "osv" | "ghsa" | "cisa_kev" | "aigently" | "mitre_atlas" | "aigently_internal";
  sourceUrl: string | null;
  publishedAt: Date | null;
  owaspRefs: string[];
  mitreAttackIds: string[];
  affectedProducts: AffectedProduct[];
  patchedVersion: string | null;
  isActivelyExploited: boolean;
  cisaActionDue: string | null;
  details: Record<string, unknown>;
  affectedStackSlugs: string[];
}

export interface SourceCount {
  fetched: number;
  upserted: number;
  skipped: number;
  errors: number;
}

export interface SyncSummary {
  npm_audit: SourceCount;
  osv:       SourceCount;
  ghsa:      SourceCount;
  nvd:       SourceCount;
  cisa_kev:  { totalKev: number; newlyFlagged: number };
}
