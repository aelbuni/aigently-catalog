import { and, eq, inArray } from "drizzle-orm";
import { db, rule, ruleStack, stack, summarizedGuardrail } from "../db/index.js";
import { computeQualityScore } from "../quality-score.js";
import { parseRuleIntoAtoms } from "./atoms.js";
import { buildCacheKey, buildBatchCacheKeys } from "./cache.js";
import { resolveConflicts } from "./conflicts.js";
import { deduplicateAtoms } from "./dedup.js";
import { createLLMClient, getModelForTask } from "./llm-client.js";
import { buildSummarizerPrompt, buildMultiLayerBatchPrompt, MULTI_LAYER_TOOL, type BatchLayerInput } from "./prompt.js";

const SUMMARIZER_VERSION = "1.0";

type ContentType = "patterns" | "deps";

type ProvenanceEntry = {
  sourceRuleIds: string[];
  resolution: "kept" | "merged" | "conflict_resolved" | "deduplicated";
};

export type LayerSummaryResult = {
  contentType: ContentType;
  summarizedContent: string;
  ruleCount: number;
  conflictCount: number;
  cacheHit: boolean;
  cacheKey: string;
};

async function fetchRulesForContentType(stackSlug: string, contentType: ContentType) {
  const rows = await db
    .select({ id: rule.id, slug: rule.slug, bodyMdx: rule.bodyMdx })
    .from(rule)
    .innerJoin(ruleStack, eq(ruleStack.ruleId, rule.id))
    .innerJoin(stack, eq(stack.id, ruleStack.stackId))
    .where(eq(stack.slug, stackSlug));

  const typePattern = contentType === "deps"
    ? /-security-deps-v\d+$/i
    : /-security-patterns-v\d+$/i;
  return rows.filter((r) => typePattern.test(r.slug));
}

function buildProvenance(atoms: ReturnType<typeof deduplicateAtoms>): Record<string, ProvenanceEntry> {
  const provenance: Record<string, ProvenanceEntry> = {};
  for (const atom of atoms) {
    const key = atom.content.slice(0, 40);
    if (!provenance[key]) {
      provenance[key] = { sourceRuleIds: [], resolution: atom.conflictResolution ?? "kept" };
    }
    if (!provenance[key].sourceRuleIds.includes(atom.sourceRuleId)) {
      provenance[key].sourceRuleIds.push(atom.sourceRuleId);
    }
  }
  return provenance;
}

async function persistGuardrail(params: {
  stackId: number;
  contentType: ContentType;
  content: string;
  sourceRuleIds: string[];
  provenance: Record<string, ProvenanceEntry>;
  conflictCount: number;
  qualityScore: number;
  cacheKey: string;
  summarizerVersion: string;
}): Promise<void> {
  const { cacheKey, stackId, contentType, content, sourceRuleIds, provenance, conflictCount, qualityScore, summarizerVersion } = params;
  await db.delete(summarizedGuardrail).where(eq(summarizedGuardrail.cacheKey, cacheKey));
  await db.insert(summarizedGuardrail).values({
    stackId,
    contentType,
    content,
    sourceRuleIds,
    provenance,
    conflictCount,
    qualityScore,
    cacheKey,
    summarizerVersion,
  });
}

/** Generate or retrieve a cached summary for a single (stack, contentType) pair. */
export async function runSummarizerForStack(
  stackSlug: string,
  contentType: ContentType,
  force = false,
): Promise<LayerSummaryResult> {
  const rules = await fetchRulesForContentType(stackSlug, contentType);
  const cacheKey = buildCacheKey(stackSlug, contentType, contentType, rules.map((r) => r.bodyMdx ?? r.id));

  const [stackRow] = await db
    .select({ id: stack.id, slug: stack.slug, name: stack.name })
    .from(stack).where(eq(stack.slug, stackSlug)).limit(1);
  if (!stackRow) throw new Error(`stack_not_found:${stackSlug}`);

  if (!force) {
    const [cached] = await db
      .select()
      .from(summarizedGuardrail)
      .where(eq(summarizedGuardrail.cacheKey, cacheKey))
      .limit(1);

    if (cached && (!cached.expiresAt || cached.expiresAt > new Date())) {
      return { contentType, summarizedContent: cached.content, ruleCount: cached.sourceRuleIds.length, conflictCount: cached.conflictCount ?? 0, cacheHit: true, cacheKey };
    }
  }

  if (rules.length === 0) {
    return { contentType, summarizedContent: "", ruleCount: 0, conflictCount: 0, cacheHit: false, cacheKey };
  }

  const atoms = rules.flatMap((r) => parseRuleIntoAtoms(r.bodyMdx ?? "", r.id, contentType));
  const { resolved, conflictCount } = resolveConflicts(atoms);
  const deduped = deduplicateAtoms(resolved);

  const model = getModelForTask("guardrail_summarization");
  const client = createLLMClient();

  // Build a minimal layer-like object so we can reuse the existing prompt builder
  const pseudoLayer = {
    id: contentType,
    slug: contentType,
    name: contentType === "patterns" ? "Security Patterns" : "Dependency Advisories",
    concernStatement: contentType === "patterns"
      ? "safe coding patterns that prevent vulnerabilities without changing dependencies"
      : "dependency vulnerability advisories requiring human confirmation before upgrading",
  };

  const batchInputs: BatchLayerInput[] = [{
    layer: pseudoLayer,
    atoms: deduped,
    sourceRuleIds: [...new Set(rules.map((r) => r.id))],
  }];

  const prompt = buildMultiLayerBatchPrompt(batchInputs, stackRow);
  let summarizedContent = "";
  let batchConflictCount = conflictCount;

  try {
    const message = await client.messages.create({
      model,
      max_tokens: 8192,
      tools: [MULTI_LAYER_TOOL],
      tool_choice: { type: "tool", name: "produce_stack_guardrails" },
      messages: [{ role: "user", content: prompt }],
    });
    const toolUse = message.content.find((b) => b.type === "tool_use");
    if (toolUse?.type === "tool_use") {
      const input = toolUse.input as { guardrails: { layerSlug: string; content: string; conflictCount: number }[] };
      const item = input.guardrails?.[0];
      if (item) {
        summarizedContent = item.content;
        batchConflictCount = item.conflictCount ?? conflictCount;
      }
    }
  } catch {
    // fall back to single-layer prompt
    const singlePrompt = buildSummarizerPrompt(deduped, [pseudoLayer], stackRow);
    const message = await client.messages.create({ model, max_tokens: 4096, messages: [{ role: "user", content: singlePrompt }] });
    summarizedContent = message.content[0]?.type === "text" ? message.content[0].text : "";
  }

  const provenance = buildProvenance(deduped);
  const qualityScore = computeQualityScore({ conflictCount: batchConflictCount, sourceRuleCount: rules.length, contentLength: summarizedContent.length, generatedAt: new Date() });

  await persistGuardrail({ stackId: stackRow.id, contentType, content: summarizedContent, sourceRuleIds: rules.map((r) => r.id), provenance, conflictCount: batchConflictCount, qualityScore, cacheKey, summarizerVersion: SUMMARIZER_VERSION });

  return { contentType, summarizedContent, ruleCount: rules.length, conflictCount: batchConflictCount, cacheHit: false, cacheKey };
}

const CONTENT_TYPES: ContentType[] = ["patterns", "deps"];

/** Bulk generate for all (stack, contentType) pairs. Pass stackSlugFilter to limit to one stack. */
export async function bulkRunSummarizer(
  mode: "empty" | "stale" | "all" = "empty",
  stackSlugFilter?: string,
): Promise<{ generated: number; skipped: number; errors: string[] }> {
  const stackRows = await db.select({ id: stack.id, slug: stack.slug }).from(stack);

  const now = new Date();
  let generated = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const stackRow of stackRows) {
    if (stackSlugFilter && stackRow.slug !== stackSlugFilter) continue;

    for (const contentType of CONTENT_TYPES) {
      const shouldGenerate = await (async () => {
        if (mode === "all") return true;
        const [existing] = await db
          .select({ id: summarizedGuardrail.id, expiresAt: summarizedGuardrail.expiresAt })
          .from(summarizedGuardrail)
          .where(and(
            eq(summarizedGuardrail.stackId, stackRow.id),
            eq(summarizedGuardrail.contentType, contentType),
          ))
          .limit(1);
        if (mode === "empty") return !existing;
        return !existing || (existing.expiresAt !== null && existing.expiresAt < now);
      })();

      if (!shouldGenerate) { skipped++; continue; }

      try {
        const result = await runSummarizerForStack(stackRow.slug, contentType, mode === "all");
        if (result.ruleCount > 0) generated++;
        else skipped++;
      } catch (e) {
        errors.push(`${stackRow.slug}/${contentType}: ${e instanceof Error ? e.message : String(e)}`);
      }

      await new Promise((r) => setTimeout(r, 300));
    }
  }

  return { generated, skipped, errors };
}
