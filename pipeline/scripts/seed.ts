import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ALL_CATALOG_STACK_SLUGS,
  COMING_SOON_STACK_SLUGS,
  isShippableThreat,
  LAUNCH_STACK_SLUGS,
  STACK_REGISTRY,
} from "@aigently/mvp-catalog";
import { and, eq, inArray, isNotNull, notInArray, sql } from "drizzle-orm";
import { CWE_TO_OWASP_WEB } from "./lib/normalise";
import { getCwePatternLines } from "./lib/cwe-patterns";

import {
  db,
  ide,
  policyTemplate,
  policyTemplateStack,
  rule,
  ruleIde,
  ruleLayerMap,
  ruleStack,
  ruleReview,
  ruleReviewHelpful,
  ruleThreatMap,
  ruleUsageDaily,
  stack,
  stackCoverageArea,
  stackFrameworkFeature,
  threat,
  threatStack,
} from "../lib/db";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const CATALOG_DIR = join(REPO_ROOT, "packages", "catalog-data");

const CONTEXT_WARN_CHARS = 450;
type RuleContentType = "patterns" | "deps";

type MasterThreat = {
  publicId: string;
  externalId?: string | null;
  cveId?: string | null;
  source?: string | null;
  sourceUrl?: string | null;
  family: string;
  name: string;
  description?: string | null;
  severity?: string | null;
  owaspRefs?: string[];
  mitreAttackIds?: string[];
  affectedProducts?: { name?: string; vulnerableVersions?: string; patchedVersions?: string }[];
  isActivelyExploited?: boolean;
  publishedAt?: string | null;
  syncedAt?: string | null;
  stacks?: string[];
  ruleHint?: string | null;
  /** Short catalog curator override for guardrail Context (plain English). */
  ruleContext?: string | null;
  /** Imperative lines; emitted as `MUST: …` one per line. */
  mustLines?: string[] | null;
  /** Overrides ALWAYS pin line when set. */
  alwaysPin?: string | null;
};

type MasterFile = {
  version?: string;
  generatedAt?: string;
  threats: MasterThreat[];
};

type ThreatStackFile = {
  threatStackRows: { threatId: string; stackSlug: string; severity: string }[];
};

// Stack metadata is now in STACK_REGISTRY (packages/mvp-catalog/src/stack-registry.ts)

function mapThreatSource(raw: string | null | undefined, sourceUrl: string): "ghsa" | "nvd" | "osv" | "cisa_kev" {
  const u = sourceUrl.toLowerCase();
  if (u.includes("nvd.nist.gov")) return "nvd";
  if (u.includes("cisa.gov")) return "cisa_kev";
  if (u.includes("github.com/advisories") || raw === "npm") return "ghsa";
  return "osv";
}

/** Fallback Context text: strip markdown noise, first ~2 sentences, ~320 char cap at sentence end. */
function compactDescription(raw: string | null | undefined): string {
  if (!raw) return "";
  const s = raw.replace(/\s+/g, " ").replace(/\*\*|#{1,6}\s?|`+/g, "").trim();
  const sentences = s.split(/(?<=[.!?])\s+/).filter(Boolean);
  let out = sentences.slice(0, 2).join(" ");
  if (out.length > 320) {
    out = out.slice(0, 320);
    const lastPeriod = Math.max(out.lastIndexOf(". "), out.lastIndexOf("! "), out.lastIndexOf("? "));
    if (lastPeriod > 120) out = out.slice(0, lastPeriod + 1);
  }
  return out.trim();
}

function pinLineFromProducts(t: MasterThreat): string {
  const products = t.affectedProducts ?? [];
  return products
    .map((p) => {
      const n = p.name ?? "package";
      const v = p.patchedVersions ?? "";
      return v ? `${n} ${v}` : n;
    })
    .join("; ");
}

function stackRuleSlug(stackSlug: string, contentType: RuleContentType): string {
  if (contentType === "patterns") return `${stackSlug}-security-patterns-v1`;
  return `${stackSlug}-security-deps-v1`;
}

function sortThreatRows(rows: MasterThreat[]): MasterThreat[] {
  const sev = (s: string | null | undefined) =>
    s === "critical" ? 0 : s === "high" ? 1 : s === "medium" ? 2 : 3;
  return [...rows].sort((a, b) => sev(a.severity) - sev(b.severity));
}

function ecosystemDependencyTreeCommand(stackSlug: string, packageName: string): string {
  const cfg = STACK_REGISTRY.find(s => s.slug === stackSlug);
  const ecosystem = cfg?.ecosystem;
  if (ecosystem === "npm") return `npm ls ${packageName}`;
  if (ecosystem === "pypi") return `python -m pip show ${packageName}`;
  if (ecosystem === "rubygems") return `bundle info ${packageName}`;
  if (ecosystem === "go") return `go mod why -m ${packageName}`;
  return `# check dependency tree for ${packageName}`;
}

function guessSafePatternsForThreat(t: MasterThreat): string[] {
  const name = `${t.name ?? ""}`.toLowerCase();
  const patterns: string[] = [];

  if (name.includes("ssrf") || name.includes("server-side request forgery")) {
    patterns.push("NEVER fetch attacker-controlled URLs from server code.");
    patterns.push("ALWAYS validate outbound request hostnames against an explicit allowlist.");
  } else if (name.includes("authorization") || name.includes("auth") || name.includes("bypass")) {
    patterns.push("NEVER rely on pathname-only middleware checks for authorization.");
    patterns.push("ALWAYS enforce authorization at the request handler boundary (API/route) as defense-in-depth.");
  } else if (name.includes("cache poison")) {
    patterns.push("NEVER cache personalized SSR responses without strict cache-control and vary discipline.");
    patterns.push("ALWAYS review caching behavior for SSR routes handling auth/session state.");
  } else if (name.includes("prototype pollution")) {
    patterns.push("NEVER merge untrusted objects into configs without guarding against prototype keys.");
    patterns.push("ALWAYS validate and sanitize user-controlled JSON before passing into library config merges.");
  } else if (name.includes("header injection")) {
    patterns.push("NEVER construct outgoing HTTP headers from untrusted input without normalization/allowlisting.");
    patterns.push("ALWAYS treat request-derived header values as untrusted data.");
  } else if (name.includes("redos") || name.includes("regular expression")) {
    patterns.push("NEVER run complex regexes on attacker-controlled strings without bounds.");
    patterns.push("ALWAYS apply length limits to user-controlled input before validation/parsing.");
  } else if (name.includes("command injection")) {
    patterns.push("NEVER evaluate templates or commands built from untrusted input.");
    patterns.push("ALWAYS treat template engines and string interpolation as a security boundary.");
  }

  return patterns;
}

/** Maps an OWASP ref back to all CWEs that resolve to it. */
function owaspRefToCwes(ref: string): string[] {
  return Object.entries(CWE_TO_OWASP_WEB)
    .filter(([, v]) => v === ref)
    .map(([k]) => k);
}

/**
 * Three-tier pattern lookup per threat:
 *   Tier 0: manual mustLines from seed-master.json  (highest priority)
 *   Tier 1: Claude-generated patternLines from threat.aiAmplification
 *   Tier 2: static CWE→ALWAYS/NEVER map
 *   Tier 3: legacy keyword heuristics (fallback)
 */
function getPatternsForThreat(
  t: MasterThreat,
  dbAmplification?: string | null
): string[] {
  if (t.mustLines && t.mustLines.length > 0) return t.mustLines;

  if (dbAmplification) {
    try {
      const parsed = JSON.parse(dbAmplification) as { patternLines?: string[] };
      if (parsed.patternLines && parsed.patternLines.length > 0) return parsed.patternLines;
    } catch { /* fall through */ }
  }

  const allCwes = (t.owaspRefs ?? []).flatMap(owaspRefToCwes);
  const cweLines = getCwePatternLines(allCwes);
  if (cweLines.length > 0) return cweLines;

  return guessSafePatternsForThreat(t);
}

/**
 * Three-tier context lookup per threat:
 *   Tier 0: manual ruleContext from seed-master.json
 *   Tier 1: Claude-generated ruleContext from threat.aiAmplification
 *   Tier 2: compactDescription from description field
 */
function getContextForThreat(
  t: MasterThreat,
  dbAmplification?: string | null
): string {
  if (t.ruleContext?.trim()) return t.ruleContext.trim();

  if (dbAmplification) {
    try {
      const parsed = JSON.parse(dbAmplification) as { ruleContext?: string };
      if (parsed.ruleContext?.trim()) return parsed.ruleContext.trim();
    } catch { /* fall through */ }
  }

  return compactDescription(t.description ?? "") || "See vendor advisory for impact.";
}

function buildStackPatternsRuleBody(
  stackSlug: string,
  rows: MasterThreat[],
  ampMap: Map<string, string>
): string {
  const stackName = STACK_REGISTRY.find(s => s.slug === stackSlug)?.name ?? stackSlug;
  const lines: string[] = [
    `# ${stackName} security patterns`,
    "",
    "Safe, always-on code patterns that reduce security risk without changing your dependency graph.",
    "",
    "These rules use ONLY pattern-level verbs (ALWAYS/NEVER). They MUST NOT prescribe dependency upgrades.",
    "",
  ];

  const sorted = sortThreatRows(rows);
  for (const t of sorted.slice(0, 24)) {
    const id = (t.cveId ?? t.publicId).trim();
    const patterns = getPatternsForThreat(t, ampMap.get(t.publicId));
    lines.push(`### ${id} — safe patterns`);
    lines.push("");
    if (patterns.length === 0) {
      lines.push("- ALWAYS follow vendor guidance when implementing features related to this advisory.");
    } else {
      for (const p of patterns) lines.push(`- ${p}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function buildStackDepsRuleBody(
  stackSlug: string,
  rows: MasterThreat[],
  ampMap: Map<string, string>
): string {
  const stackName = STACK_REGISTRY.find(s => s.slug === stackSlug)?.name ?? stackSlug;
  const lines: string[] = [
    `# ${stackName} security dependency alerts`,
    "",
    "Dependency-related security advisories. These instructions MUST NOT automatically edit dependency files.",
    "",
    "Verb contract: WARN + CONFIRM + CHECK. No ALWAYS pinning or silent upgrades.",
    "",
  ];

  const sorted = sortThreatRows(rows);
  for (const t of sorted.slice(0, 24)) {
    const id = (t.cveId ?? t.publicId).trim();
    const sourceUrl = (t.sourceUrl ?? "").trim();
    const pkg = (t.affectedProducts?.[0]?.name ?? "").trim();
    const patched = (t.alwaysPin ?? "").trim() || pinLineFromProducts(t);
    let context = getContextForThreat(t, ampMap.get(t.publicId));
    if (t.isActivelyExploited && !/actively exploited/i.test(context)) {
      context = `${context} Actively exploited in the wild.`.trim();
    }
    if (context.length > CONTEXT_WARN_CHARS) {
      console.warn(
        `Gate 2 warning: threat ${id} Context length ${context.length} chars (budget ≤${CONTEXT_WARN_CHARS}); consider shortening ruleContext in seed-master.json`
      );
    }

    lines.push(`### ${id} — ${t.name}`);
    lines.push("");
    lines.push(`Context: ${context}`);
    if (sourceUrl) lines.push(`Source: ${sourceUrl}`);
    lines.push("");

    if (pkg) {
      const treeCmd = ecosystemDependencyTreeCommand(stackSlug, pkg);
      lines.push(`WHEN you detect \`${pkg}\` in this project at a vulnerable version:`);
      lines.push("");
      lines.push(
        `WARN the developer: ⚠️ ${id}: ${pkg} may be vulnerable. ${context} Patched versions: ${patched || "(see advisory)"}`
      );
      lines.push("");
      lines.push("CHECK for dependency conflicts before proposing any upgrade:");
      lines.push(`Run: \`${treeCmd}\``);
      lines.push("");
      lines.push("DO NOT modify dependency files without developer confirmation.");
      lines.push("");
      lines.push("WHEN the developer confirms they want to upgrade:");
      lines.push("1. Show the dependency tree output and identify conflicts");
      lines.push("2. Propose a migration plan (including breaking changes) before editing files");
      lines.push("3. Only then apply the upgrade");
    } else {
      lines.push("WHEN you detect a vulnerable dependency related to this advisory:");
      lines.push("");
      lines.push(`WARN the developer: ⚠️ ${id}: A dependency in this project may be vulnerable. ${context}`);
      lines.push("DO NOT modify dependency files without developer confirmation.");
    }

    lines.push("");
    lines.push("---");
    lines.push("");
  }

  return lines.join("\n");
}

function imperativeLineCount(body: string): number {
  return body
    .split("\n")
    .filter((line) => /^\s*-?\s*(NEVER|ALWAYS|MUST:|MUST\b|WARN\b|CONFIRM\b|CHECK\b|DO NOT\b)/i.test(line.trim())).length;
}

async function clearCatalog() {
  await db.delete(ruleThreatMap);
  await db.delete(ruleUsageDaily);
  await db.delete(ruleReviewHelpful);
  await db.delete(ruleReview);
  await db.delete(ruleIde);
  await db.delete(ruleLayerMap);
  await db.delete(ruleStack);
  await db.delete(rule);
  await db.delete(threatStack);
  await db.delete(threat);
  await db.delete(policyTemplateStack);
  await db.delete(policyTemplate);
  await db.delete(stackFrameworkFeature);
  await db.delete(stackCoverageArea);
  await db.delete(stack).where(inArray(stack.slug, [...ALL_CATALOG_STACK_SLUGS]));
}

async function upsertCatalogStacks() {
  await Promise.all(
    STACK_REGISTRY.map(cfg =>
      db
        .insert(stack)
        .values({
          slug:          cfg.slug,
          name:          cfg.name,
          sortOrder:     cfg.sortOrder,
          catalogStatus: cfg.catalogStatus,
          ecosystem:     cfg.ecosystem,
          nvdKeywords:   cfg.nvdKeywords,
          osvEcosystem:  cfg.osvEcosystem,
          securityGrade: null,
          gradeRationale: null,
        })
        .onConflictDoUpdate({
          target: stack.slug,
          set: {
            name:          cfg.name,
            sortOrder:     cfg.sortOrder,
            catalogStatus: cfg.catalogStatus,
            ecosystem:     cfg.ecosystem,
            nvdKeywords:   cfg.nvdKeywords,
            osvEcosystem:  cfg.osvEcosystem,
          },
        })
    )
  );
}

async function insertThreatsAndStacks(
  shipped: MasterThreat[],
  shipIds: Set<string>,
  threatStacks: ThreatStackFile,
  stackIdBySlug: Map<string, number>
) {
  for (const t of shipped) {
    const src = mapThreatSource(t.source ?? null, (t.sourceUrl ?? "").trim());
    const syncedAt = t.syncedAt ? new Date(t.syncedAt) : new Date();
    const publishedAt = t.publishedAt ? new Date(t.publishedAt) : null;
    const products = Array.isArray(t.affectedProducts) ? t.affectedProducts : [];
    await db
      .insert(threat)
      .values({
        publicId: t.publicId,
        family: t.family as "owasp_web" | "owasp_llm" | "mitre_atlas" | "vibe_coding",
        name: t.name,
        severity: (t.severity ?? "medium") as "critical" | "high" | "medium" | "low" | "info",
        description: t.description ?? undefined,
        cveId: t.cveId ?? undefined,
        externalId: (t.externalId ?? t.publicId).trim(),
        source: src,
        sourceUrl: (t.sourceUrl ?? "").trim(),
        publishedAt,
        syncedAt,
        owaspRefs: [...(t.owaspRefs ?? [])],
        mitreAttackIds: [...(t.mitreAttackIds ?? [])],
        affectedProducts: products as unknown as Record<string, unknown>,
        isActivelyExploited: t.isActivelyExploited ?? false,
      })
      .onConflictDoUpdate({
        target: threat.publicId,
        set: {
          name: t.name,
          severity: (t.severity ?? "medium") as "critical" | "high" | "medium" | "low" | "info",
          description: t.description ?? null,
          cveId: t.cveId ?? null,
          externalId: (t.externalId ?? t.publicId).trim(),
          source: src,
          sourceUrl: (t.sourceUrl ?? "").trim(),
          syncedAt,
          owaspRefs: [...(t.owaspRefs ?? [])],
          mitreAttackIds: [...(t.mitreAttackIds ?? [])],
          affectedProducts: products as unknown as Record<string, unknown>,
          isActivelyExploited: t.isActivelyExploited ?? false,
          updatedAt: new Date(),
        },
      });
  }

  for (const row of threatStacks.threatStackRows) {
    if (!shipIds.has(row.threatId)) continue;
    const sid = stackIdBySlug.get(row.stackSlug);
    if (sid === undefined) continue;
    await db
      .insert(threatStack)
      .values({
        threatId: row.threatId,
        stackId: sid,
        severity: row.severity as "critical" | "high" | "medium" | "low" | "info",
        isMitigatedByRules: false,
      })
      .onConflictDoUpdate({
        target: [threatStack.threatId, threatStack.stackId],
        set: {
          severity: row.severity as "critical" | "high" | "medium" | "low" | "info",
        },
      });
  }
}

async function reconcileRuleForStack(
  ruleId: string,
  stackId: number,
  ideIdBySlug: Map<string, number | undefined>
) {
  await db.delete(ruleStack).where(eq(ruleStack.ruleId, ruleId));
  await db.insert(ruleStack).values({ ruleId, stackId });

  const desiredRows = await db
    .select({ publicId: threat.publicId })
    .from(threatStack)
    .innerJoin(threat, eq(threatStack.threatId, threat.publicId))
    .where(eq(threatStack.stackId, stackId));
  const ids = desiredRows.map((r) => r.publicId);

  if (ids.length > 0) {
    await db
      .delete(ruleThreatMap)
      .where(and(eq(ruleThreatMap.ruleId, ruleId), notInArray(ruleThreatMap.threatId, ids)));
  }
  for (const threatId of ids) {
    await db.insert(ruleThreatMap).values({ ruleId, threatId }).onConflictDoNothing();
  }

  for (const ideSlug of ["cursor", "claude-code", "windsurf", "copilot", "cline"] as const) {
    const ideId = ideIdBySlug.get(ideSlug);
    if (ideId !== undefined) {
      await db.insert(ruleIde).values({ ruleId, ideId }).onConflictDoNothing();
    }
  }

  await db.delete(ruleLayerMap).where(eq(ruleLayerMap.ruleId, ruleId));
  await db.insert(ruleLayerMap).values({ ruleId, layer: "security" }).onConflictDoNothing();
}

function todayDateStr(): string {
  return new Date().toISOString().slice(0, 10);
}

async function seedUpsert(master: MasterFile, threatStacks: ThreatStackFile, shipped: MasterThreat[]) {
  const shipIds = new Set(shipped.map((t) => t.publicId));

  await upsertCatalogStacks();

  await db
    .insert(ide)
    .values([
      { slug: "cursor", name: "Cursor", sortOrder: 1 },
      { slug: "claude-code", name: "Claude Code", sortOrder: 2 },
      { slug: "windsurf", name: "Windsurf", sortOrder: 3 },
      { slug: "cline", name: "Cline", sortOrder: 4 },
      { slug: "copilot", name: "GitHub Copilot", sortOrder: 5 },
    ])
    .onConflictDoNothing({ target: ide.slug });

  const stackRows = await db.select().from(stack).where(inArray(stack.slug, [...ALL_CATALOG_STACK_SLUGS]));
  const stackIdBySlug = new Map(stackRows.map((s) => [s.slug, s.id]));

  await insertThreatsAndStacks(shipped, shipIds, threatStacks, stackIdBySlug);

  const ideRows = await db.select().from(ide);
  const ideIdBySlug = new Map(ideRows.map((i) => [i.slug, i.id]));

  // Load Claude-generated amplification for all threats at once
  const ampRows = await db
    .select({ publicId: threat.publicId, aiAmplification: threat.aiAmplification })
    .from(threat)
    .where(isNotNull(threat.aiAmplification));
  const ampMap = new Map(ampRows.map(r => [r.publicId, r.aiAmplification!]));

  const threatsByStack = new Map<string, MasterThreat[]>();
  for (const t of shipped) {
    for (const s of t.stacks ?? []) {
      if (!(LAUNCH_STACK_SLUGS as readonly string[]).includes(s)) continue;
      const arr = threatsByStack.get(s) ?? [];
      arr.push(t);
      threatsByStack.set(s, arr);
    }
  }

  for (const stackSlug of LAUNCH_STACK_SLUGS) {
    const stackId = stackIdBySlug.get(stackSlug)!;
    const stackThreats = threatsByStack.get(stackSlug) ?? [];
    const stackMeta = STACK_REGISTRY.find(s => s.slug === stackSlug)!;
    const stackMetaName = stackMeta?.name ?? stackSlug;

    for (const contentType of ["patterns", "deps"] as const) {
      const slug = stackRuleSlug(stackSlug, contentType);
      const body =
        contentType === "patterns"
          ? buildStackPatternsRuleBody(stackSlug, stackThreats, ampMap)
          : buildStackDepsRuleBody(stackSlug, stackThreats, ampMap);

      const name =
        contentType === "patterns"
          ? `${stackMetaName} security patterns`
          : `${stackMetaName} security dependency alerts`;
      const description =
        contentType === "patterns"
          ? `Always-on secure coding patterns for ${stackMetaName} (safe; no dependency edits).`
          : `Dependency vulnerability alerts for ${stackMetaName} (advisory; requires confirmation).`;

      const [upserted] = await db
        .insert(rule)
        .values({
          slug,
          name,
          description,
          version: "1.0.0",
          dateAdded: "2026-05-06",
          lastUpdated: todayDateStr(),
          author: "aigently",
          certified: true,
          lineCount: body.split("\n").length,
          bodyMdx: body,
        })
        .onConflictDoUpdate({
          target: rule.slug,
          set: {
            name,
            description,
            version: "1.0.0",
            lastUpdated: todayDateStr(),
            lineCount: body.split("\n").length,
            bodyMdx: body,
            updatedAt: new Date(),
          },
        })
        .returning({ id: rule.id });

      const ruleId = upserted!.id;
      await reconcileRuleForStack(ruleId, stackId, ideIdBySlug);
    }
  }

  // Remove legacy guardrails slugs now superseded by patterns+deps split.
  for (const stackSlug of LAUNCH_STACK_SLUGS) {
    const legacySlug = `${stackSlug}-security-guardrails-v1`;
    await db.delete(rule).where(eq(rule.slug, legacySlug));
  }

  console.log(
    `Seed upsert complete: ${shipped.length} shippable threats, rules upserted for ${
      LAUNCH_STACK_SLUGS.length * 2
    } rules across ${LAUNCH_STACK_SLUGS.length} launch stacks (catalog from ${master.generatedAt ?? "seed-master.json"}).`
  );
}

async function seedFull(master: MasterFile, threatStacks: ThreatStackFile, shipped: MasterThreat[]) {
  const shipIds = new Set(shipped.map((t) => t.publicId));

  await clearCatalog();

  for (const cfg of STACK_REGISTRY) {
    await db.insert(stack).values({
      slug:          cfg.slug,
      name:          cfg.name,
      sortOrder:     cfg.sortOrder,
      catalogStatus: cfg.catalogStatus,
      ecosystem:     cfg.ecosystem,
      nvdKeywords:   cfg.nvdKeywords,
      osvEcosystem:  cfg.osvEcosystem,
      securityGrade: null,
      gradeRationale: null,
    });
  }

  await db
    .insert(ide)
    .values([
      { slug: "cursor", name: "Cursor", sortOrder: 1 },
      { slug: "claude-code", name: "Claude Code", sortOrder: 2 },
      { slug: "windsurf", name: "Windsurf", sortOrder: 3 },
      { slug: "cline", name: "Cline", sortOrder: 4 },
      { slug: "copilot", name: "GitHub Copilot", sortOrder: 5 },
    ])
    .onConflictDoNothing({ target: ide.slug });

  const stackRows = await db.select().from(stack).where(inArray(stack.slug, [...ALL_CATALOG_STACK_SLUGS]));
  const stackIdBySlug = new Map(stackRows.map((s) => [s.slug, s.id]));

  await insertThreatsAndStacks(shipped, shipIds, threatStacks, stackIdBySlug);

  const ideRows = await db.select().from(ide);
  const ideIdBySlug = new Map(ideRows.map((i) => [i.slug, i.id]));

  // Load Claude-generated amplification for all threats at once
  const ampRows = await db
    .select({ publicId: threat.publicId, aiAmplification: threat.aiAmplification })
    .from(threat)
    .where(isNotNull(threat.aiAmplification));
  const ampMap = new Map(ampRows.map(r => [r.publicId, r.aiAmplification!]));

  const threatsByStack = new Map<string, MasterThreat[]>();
  for (const t of shipped) {
    for (const s of t.stacks ?? []) {
      if (!(LAUNCH_STACK_SLUGS as readonly string[]).includes(s)) continue;
      const arr = threatsByStack.get(s) ?? [];
      arr.push(t);
      threatsByStack.set(s, arr);
    }
  }

  for (const stackSlug of LAUNCH_STACK_SLUGS) {
    const stackId = stackIdBySlug.get(stackSlug)!;
    const stackThreats = threatsByStack.get(stackSlug) ?? [];
    const stackMetaName = STACK_REGISTRY.find(s => s.slug === stackSlug)?.name ?? stackSlug;

    for (const contentType of ["patterns", "deps"] as const) {
      const slug = stackRuleSlug(stackSlug, contentType);
      const body =
        contentType === "patterns"
          ? buildStackPatternsRuleBody(stackSlug, stackThreats, ampMap)
          : buildStackDepsRuleBody(stackSlug, stackThreats, ampMap);
      const name =
        contentType === "patterns"
          ? `${stackMetaName} security patterns`
          : `${stackMetaName} security dependency alerts`;
      const description =
        contentType === "patterns"
          ? `Always-on secure coding patterns for ${stackMetaName} (safe; no dependency edits).`
          : `Dependency vulnerability alerts for ${stackMetaName} (advisory; requires confirmation).`;

      const insertedRule = await db
        .insert(rule)
        .values({
          slug,
          name,
          description,
          version: "1.0.0",
          dateAdded: "2026-05-06",
          lastUpdated: todayDateStr(),
          author: "aigently",
          certified: true,
          lineCount: body.split("\n").length,
          bodyMdx: body,
        })
        .returning({ id: rule.id });

      const ruleId = insertedRule[0]!.id;
      await db.insert(ruleStack).values({ ruleId, stackId }).onConflictDoNothing();
      for (const ideSlug of ["cursor", "claude-code", "windsurf", "copilot", "cline"] as const) {
        const ideId = ideIdBySlug.get(ideSlug);
        if (ideId !== undefined) {
          await db.insert(ruleIde).values({ ruleId, ideId }).onConflictDoNothing();
        }
      }
      await db.insert(ruleLayerMap).values({ ruleId, layer: "security" }).onConflictDoNothing();

      const linkThreats = await db
        .select({ publicId: threat.publicId })
        .from(threatStack)
        .innerJoin(threat, eq(threatStack.threatId, threat.publicId))
        .where(eq(threatStack.stackId, stackId));

      for (const { publicId } of linkThreats) {
        await db.insert(ruleThreatMap).values({ ruleId, threatId: publicId }).onConflictDoNothing();
      }
    }
  }

  console.log(
    `Seed complete: ${shipped.length} shippable threats, stacks launch+coming_soon, ${
      LAUNCH_STACK_SLUGS.length * 2
    } rules (catalog from ${master.generatedAt ?? "seed-master.json"}).`
  );
}

async function runGates() {
  const certifiedRules = await db.select({ id: rule.id, slug: rule.slug }).from(rule).where(eq(rule.certified, true));
  for (const r of certifiedRules) {
    const [cnt] = await db
      .select({ n: sql<number>`count(*)::int` })
      .from(ruleThreatMap)
      .where(eq(ruleThreatMap.ruleId, r.id));
    if ((cnt?.n ?? 0) < 1) {
      throw new Error(`Gate 1 failed: certified rule ${r.slug} has no rule_threat_map rows`);
    }
  }

  for (const r of await db.select().from(rule)) {
    const n = imperativeLineCount(r.bodyMdx ?? "");
    if (n < 10) {
      console.warn(`Gate 2 warning: rule ${r.slug} has ${n} imperative lines (target ≥10)`);
    }
  }
}

async function main() {
  const masterRaw = readFileSync(join(CATALOG_DIR, "seed-master.json"), "utf8");
  const tsRaw = readFileSync(join(CATALOG_DIR, "seed-threat-stack.json"), "utf8");
  const master = JSON.parse(masterRaw) as MasterFile;
  const threatStacks = JSON.parse(tsRaw) as ThreatStackFile;

  const shipped = master.threats.filter((t) =>
    isShippableThreat({
      publicId: t.publicId,
      cveId: t.cveId,
      sourceUrl: t.sourceUrl,
    })
  );

  const mode = process.env.SEED_MODE === "upsert" ? "upsert" : "full";
  if (mode === "upsert") {
    await seedUpsert(master, threatStacks, shipped);
  } else {
    await seedFull(master, threatStacks, shipped);
  }

  await runGates();

  if (process.env.SEED_URL_HEAD_CHECK === "1") {
    const urlRows = await db.select({ url: threat.sourceUrl }).from(threat);
    const seen = new Set<string>();
    for (const { url } of urlRows) {
      if (!url || seen.has(url)) continue;
      seen.add(url);
      try {
        const res = await fetch(url, { method: "HEAD", redirect: "follow" });
        if (!res.ok) console.warn(`HEAD ${url} → ${res.status}`);
      } catch (e) {
        console.warn(`HEAD failed ${url}`, e);
      }
    }
  }
}

function isConnRefused(err: unknown): boolean {
  const e = err as { cause?: { code?: string; errors?: { code?: string }[] } };
  if (e?.cause?.code === "ECONNREFUSED") return true;
  const nested = e?.cause?.errors;
  if (Array.isArray(nested) && nested.some((x) => x?.code === "ECONNREFUSED")) return true;
  return (err as NodeJS.ErrnoException)?.code === "ECONNREFUSED";
}

main().catch((e) => {
  if (isConnRefused(e)) {
    console.error(
      "Cannot reach PostgreSQL (ECONNREFUSED). From repo root run: npm run db:up\n" +
        "Then check DATABASE_URL in pipeline/.env (default postgresql://aigently:aigently@localhost:5433/aigently)."
    );
  }
  console.error(e);
  process.exit(1);
});
