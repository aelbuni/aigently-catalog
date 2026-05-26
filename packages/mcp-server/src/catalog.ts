import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Works both in the monorepo (dist/ sibling of catalog-data/) and when installed via npm
// (dist/catalog-data/ is copied in by the build script).
const CATALOG_DIR = path.resolve(__dirname, "catalog-data");

export interface CatalogStack {
  slug: string;
  name: string;
  ecosystem: string | null;
  catalogStatus: string;
  securityGrade: string | null;
  sortOrder: number;
}

export interface AiAmplification {
  patternLines: string[];
  ruleContext: string;
  generatedAt: string;
  model: string;
}

export interface CatalogThreat {
  publicId: string;
  cveId: string | null;
  source: string;
  sourceUrl: string | null;
  family: string;
  name: string;
  description: string | null;
  severity: string | null;
  owaspRefs: string[];
  isActivelyExploited: boolean;
  affectedProducts: unknown;
  // The pipeline exports aiAmplification as a JSON object (jsonb column).
  // Some older exports serialised it as a JSON string — handle both.
  aiAmplification: AiAmplification | string | null;
  publishedAt: string | null;
  syncedAt: string | null;
  stacks: string[];
  layers: string[]; // layer slugs assigned by the pipeline (threatLayer table)
}

export interface CatalogRule {
  id: string;
  slug: string;
  name: string;
  description: string;
  version: string;
  ruleType?: string;      // "pattern" | "deps" | null
  strengthScore?: number;
  bodyMdx: string | null;
  summaryMdx: string | null;
  stacks: string[];
  layers: string[];   // layer slugs from ruleLayerMap
  ides: string[];     // IDE slugs from ruleIde; empty = applies to all IDEs
  threatIds: string[];
}

export interface CatalogGuardrail {
  stackSlug: string;
  layerSlug: string;
  content: string;
  // Pipeline metadata — useful for freshness checks and quality filtering
  qualityScore: number | null;
  scoreOverride: number | null;
  conflictCount: number | null;
  sourceRuleIds: string[];
  summarizerVersion: string | null;
  generatedAt: string | null;
  cacheKey: string | null;
}

export interface Manifest {
  version: string;
  generatedAt: string;
  counts: { threats: number; rules: number; stacks: number; guardrails?: number };
}

function load<T>(filename: string): T {
  const fullPath = path.join(CATALOG_DIR, filename);
  if (!fs.existsSync(fullPath)) {
    throw new Error(
      `Catalog file not found: ${fullPath}\n` +
      `Run the export pipeline: npm run export:catalog -w @aigently/pipeline`
    );
  }
  try {
    return JSON.parse(fs.readFileSync(fullPath, "utf8")) as T;
  } catch (err) {
    throw new Error(`Failed to parse ${filename}: ${(err as Error).message}`);
  }
}

// Lazy singletons — loaded once per process
let _stacks:     CatalogStack[]     | null = null;
let _threats:    CatalogThreat[]    | null = null;
let _rules:      CatalogRule[]      | null = null;
let _guardrails: CatalogGuardrail[] | null = null;
let _manifest:   Manifest           | null = null;

export function getStacks():     CatalogStack[]     { return (_stacks     ??= load<CatalogStack[]>("stacks.json")); }
export function getThreats():    CatalogThreat[]    { return (_threats    ??= load<CatalogThreat[]>("threats.json")); }
export function getRules():      CatalogRule[]      { return (_rules      ??= load<CatalogRule[]>("rules.json")); }
export function getGuardrails(): CatalogGuardrail[] { return (_guardrails ??= load<CatalogGuardrail[]>("guardrails.json")); }
export function getManifest():   Manifest           { return (_manifest   ??= load<Manifest>("manifest.json")); }

/** Parse aiAmplification — handles both JSON-object (new exports) and JSON-string (legacy) formats. */
export function parseAmplification(raw: AiAmplification | string | null): AiAmplification | null {
  if (!raw) return null;
  if (typeof raw === "object") return raw;
  try { return JSON.parse(raw) as AiAmplification; } catch { return null; }
}
