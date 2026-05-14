import { and, eq } from "drizzle-orm";
import { db, layer, rule, ruleLayerMap, ruleStack, stack, summarizedGuardrail } from "../db/index.js";
import { computeQualityScore } from "../quality-score.js";
import { parseRuleIntoAtoms } from "./atoms.js";
import { buildCacheKey, buildBatchCacheKeys } from "./cache.js";
import { resolveConflicts } from "./conflicts.js";
import { deduplicateAtoms } from "./dedup.js";
import { createLLMClient, getModelForTask } from "./llm-client.js";
import { buildSummarizerPrompt, buildMultiLayerBatchPrompt, MULTI_LAYER_TOOL, type BatchLayerInput } from "./prompt.js";

const SUMMARIZER_VERSION = "1.0";

type ProvenanceEntry = {
  sourceRuleIds: string[];
  resolution: "kept" | "merged" | "conflict_resolved" | "deduplicated";
};

export type LayerSummaryResult = {
  layerSlug: string;
  layerName: string;
  summarizedContent: string;
  ruleCount: number;
  conflictCount: number;
  cacheHit: boolean;
  cacheKey: string;
};

async function fetchRulesForLayer(stackSlug: string, layerSlug: string, ruleType?: string) {
  const rows = await db
    .select({ id: rule.id, slug: rule.slug, bodyMdx: rule.bodyMdx })
    .from(rule)
    .innerJoin(ruleStack, eq(ruleStack.ruleId, rule.id))
    .innerJoin(stack, eq(stack.id, ruleStack.stackId))
    .innerJoin(ruleLayerMap, eq(ruleLayerMap.ruleId, rule.id))
    .innerJoin(layer, eq(layer.id, ruleLayerMap.layerId))
    .where(and(eq(stack.slug, stackSlug), eq(layer.slug, layerSlug)));

  if (!ruleType || ruleType === "all") return rows;
  const typePattern = ruleType === "deps" ? /-security-deps-v\d+$/i : /-security-patterns-v\d+$/i;
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
  layerId: string;
  ideSlug: string;
  content: string;
  sourceRuleIds: string[];
  provenance: Record<string, ProvenanceEntry>;
  conflictCount: number;
  qualityScore: number;
  cacheKey: string;
  summarizerVersion: string;
}): Promise<void> {
  const { cacheKey, stackId, layerId, ideSlug, content, sourceRuleIds, provenance, conflictCount, qualityScore, summarizerVersion } = params;
  await db.delete(summarizedGuardrail).where(eq(summarizedGuardrail.cacheKey, cacheKey));
  await db.insert(summarizedGuardrail).values({
    stackId,
    layerId,
    ideSlug,
    content,
    sourceRuleIds,
    provenance,
    conflictCount,
    qualityScore,
    cacheKey,
    summarizerVersion,
  });
}

/** Generate or retrieve a cached summary for a single (stack, layer) pair. */
export async function runSummarizerForLayer(
  stackSlug: string,
  layerSlug: string,
  ruleType = "all",
  previousScore?: number,
): Promise<LayerSummaryResult> {
  const rules = await fetchRulesForLayer(stackSlug, layerSlug, ruleType);
  const cacheKey = buildCacheKey(stackSlug, layerSlug, ruleType, rules.map((r) => r.bodyMdx ?? r.id));

  const [cached] = await db
    .select()
    .from(summarizedGuardrail)
    .where(eq(summarizedGuardrail.cacheKey, cacheKey))
    .limit(1);

  if (cached && (!cached.expiresAt || cached.expiresAt > new Date())) {
    const [layerRow] = await db.select({ name: layer.name }).from(layer).where(eq(layer.slug, layerSlug)).limit(1);
    return { layerSlug, layerName: layerRow?.name ?? layerSlug, summarizedContent: cached.content, ruleCount: cached.sourceRuleIds.length, conflictCount: cached.conflictCount ?? 0, cacheHit: true, cacheKey };
  }

  if (rules.length === 0) {
    return { layerSlug, layerName: layerSlug, summarizedContent: "", ruleCount: 0, conflictCount: 0, cacheHit: false, cacheKey };
  }

  const [layerRow] = await db
    .select({ id: layer.id, slug: layer.slug, name: layer.name, concernStatement: layer.concernStatement })
    .from(layer).where(eq(layer.slug, layerSlug)).limit(1);
  if (!layerRow) throw new Error(`layer_not_found:${layerSlug}`);

  const [stackRow] = await db
    .select({ id: stack.id, slug: stack.slug, name: stack.name })
    .from(stack).where(eq(stack.slug, stackSlug)).limit(1);
  if (!stackRow) throw new Error("stack_not_found");

  const atoms = rules.flatMap((r) => parseRuleIntoAtoms(r.bodyMdx ?? "", r.id, layerSlug));
  const { resolved, conflictCount } = resolveConflicts(atoms);
  const deduped = deduplicateAtoms(resolved);

  const model = getModelForTask("guardrail_summarization");
  const client = createLLMClient();

  const prompt = buildSummarizerPrompt(deduped, [{ ...layerRow, concernStatement: layerRow.concernStatement ?? "" }], stackRow, previousScore);
  const message = await client.messages.create({ model, max_tokens: 4096, messages: [{ role: "user", content: prompt }] });

  const summarizedContent = message.content[0]?.type === "text" ? message.content[0].text : "";
  const provenance = buildProvenance(deduped);
  const qualityScore = computeQualityScore({ conflictCount, sourceRuleCount: rules.length, contentLength: summarizedContent.length, generatedAt: new Date() });

  await persistGuardrail({ stackId: stackRow.id, layerId: layerRow.id, ideSlug: "all", content: summarizedContent, sourceRuleIds: rules.map((r) => r.id), provenance, conflictCount, qualityScore, cacheKey, summarizerVersion: SUMMARIZER_VERSION });

  return { layerSlug, layerName: layerRow.name, summarizedContent, ruleCount: rules.length, conflictCount, cacheHit: false, cacheKey };
}

/** Batch summarizer for all layers of a single stack in one LLM call. Falls back per-layer for any skipped. */
export async function runSummarizerForStack(
  stackSlug: string,
  layerSlugs: string[],
  ruleType = "all",
  onLayerComplete?: (result: LayerSummaryResult) => void,
  force = false,
): Promise<LayerSummaryResult[]> {
  if (layerSlugs.length === 0) return [];

  const [stackRow] = await db
    .select({ id: stack.id, slug: stack.slug, name: stack.name })
    .from(stack).where(eq(stack.slug, stackSlug)).limit(1);
  if (!stackRow) throw new Error(`stack_not_found:${stackSlug}`);

  const layerData = await Promise.all(
    layerSlugs.map(async (layerSlug) => {
      const [rules, layerRow] = await Promise.all([
        fetchRulesForLayer(stackSlug, layerSlug, ruleType),
        db.select({ id: layer.id, slug: layer.slug, name: layer.name, concernStatement: layer.concernStatement })
          .from(layer).where(eq(layer.slug, layerSlug)).limit(1).then((r) => r[0]),
      ]);
      return { layerSlug, rules, layerRow };
    })
  );

  const layerRuleContents: Record<string, string[]> = {};
  for (const { layerSlug, rules } of layerData) {
    layerRuleContents[layerSlug] = rules.map((r) => r.bodyMdx ?? r.id);
  }
  const cacheKeys = buildBatchCacheKeys(stackSlug, ruleType, layerRuleContents);

  const results: LayerSummaryResult[] = [];
  const toGenerate: typeof layerData = [];

  for (const ld of layerData) {
    const { layerSlug, rules, layerRow } = ld;
    const cacheKey = cacheKeys[layerSlug];

    if (rules.length === 0) {
      const result: LayerSummaryResult = { layerSlug, layerName: layerRow?.name ?? layerSlug, summarizedContent: "", ruleCount: 0, conflictCount: 0, cacheHit: false, cacheKey };
      results.push(result);
      onLayerComplete?.(result);
      continue;
    }

    if (!force) {
      const [cached] = await db.select().from(summarizedGuardrail).where(eq(summarizedGuardrail.cacheKey, cacheKey)).limit(1);
      if (cached && (!cached.expiresAt || cached.expiresAt > new Date())) {
        const result: LayerSummaryResult = { layerSlug, layerName: layerRow?.name ?? layerSlug, summarizedContent: cached.content, ruleCount: cached.sourceRuleIds.length, conflictCount: cached.conflictCount ?? 0, cacheHit: true, cacheKey };
        results.push(result);
        onLayerComplete?.(result);
        continue;
      }
    }

    toGenerate.push(ld);
  }

  if (toGenerate.length === 0) return results;

  const batchInputs: BatchLayerInput[] = toGenerate
    .filter((ld) => ld.layerRow !== undefined)
    .map(({ layerSlug, rules, layerRow }) => {
      const atoms = rules.flatMap((r) => parseRuleIntoAtoms(r.bodyMdx ?? "", r.id, layerSlug));
      const { resolved } = resolveConflicts(atoms);
      const deduped = deduplicateAtoms(resolved);
      return { layer: { ...layerRow!, concernStatement: layerRow!.concernStatement ?? "" }, atoms: deduped, sourceRuleIds: [...new Set(rules.map((r) => r.id))] };
    });

  const model = getModelForTask("guardrail_summarization");
  const client = createLLMClient();
  const prompt = buildMultiLayerBatchPrompt(batchInputs, stackRow);

  let toolResponse: { layerSlug: string; content: string; conflictCount: number }[] = [];
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
      toolResponse = input.guardrails ?? [];
    }
  } catch {
    // fall through to per-layer fallback
  }

  const respondedSlugs = new Set<string>();
  for (const item of toolResponse) {
    const ld = toGenerate.find((d) => d.layerSlug === item.layerSlug);
    if (!ld || !ld.layerRow) continue;

    const { layerSlug, rules, layerRow } = ld;
    const cacheKey = cacheKeys[layerSlug];
    respondedSlugs.add(layerSlug);

    const atoms = rules.flatMap((r) => parseRuleIntoAtoms(r.bodyMdx ?? "", r.id, layerSlug));
    const { resolved, conflictCount } = resolveConflicts(atoms);
    const deduped = deduplicateAtoms(resolved);
    const provenance = buildProvenance(deduped);
    const batchQualityScore = computeQualityScore({ conflictCount: item.conflictCount ?? conflictCount, sourceRuleCount: rules.length, contentLength: item.content.length, generatedAt: new Date() });

    await persistGuardrail({ stackId: stackRow.id, layerId: layerRow.id, ideSlug: "all", content: item.content, sourceRuleIds: rules.map((r) => r.id), provenance, conflictCount: item.conflictCount ?? conflictCount, qualityScore: batchQualityScore, cacheKey, summarizerVersion: SUMMARIZER_VERSION });

    const result: LayerSummaryResult = { layerSlug, layerName: layerRow.name, summarizedContent: item.content, ruleCount: rules.length, conflictCount: item.conflictCount ?? conflictCount, cacheHit: false, cacheKey };
    results.push(result);
    onLayerComplete?.(result);
  }

  for (const { layerSlug } of toGenerate.filter((ld) => !respondedSlugs.has(ld.layerSlug))) {
    const result = await runSummarizerForLayer(stackSlug, layerSlug, ruleType);
    results.push(result);
    onLayerComplete?.(result);
  }

  return results;
}

/** Bulk generate for all (stack, layer) pairs that have rules. Pass stackSlugFilter to limit to one stack. */
export async function bulkRunSummarizer(
  mode: "empty" | "stale" | "all" = "empty",
  stackSlugFilter?: string,
): Promise<{ generated: number; skipped: number; errors: string[] }> {
  const pairs = await db
    .selectDistinct({ stackSlug: stack.slug, layerSlug: layer.slug, stackId: stack.id, layerId: layer.id })
    .from(rule)
    .innerJoin(ruleStack, eq(ruleStack.ruleId, rule.id))
    .innerJoin(stack, eq(stack.id, ruleStack.stackId))
    .innerJoin(ruleLayerMap, eq(ruleLayerMap.ruleId, rule.id))
    .innerJoin(layer, eq(layer.id, ruleLayerMap.layerId));

  const now = new Date();
  let generated = 0;
  const errors: string[] = [];

  const stackGroups = new Map<string, string[]>();
  for (const pair of pairs) {
    const existing = stackGroups.get(pair.stackSlug) ?? [];
    existing.push(pair.layerSlug);
    stackGroups.set(pair.stackSlug, existing);
  }

  for (const [stackSlug, allLayerSlugs] of stackGroups) {
    if (stackSlugFilter && stackSlug !== stackSlugFilter) continue;
    const layerSlugsToProcess: string[] = [];

    for (const layerSlug of allLayerSlugs) {
      const pair = pairs.find((p) => p.stackSlug === stackSlug && p.layerSlug === layerSlug)!;
      const shouldGenerate = await (async () => {
        if (mode === "all") return true;
        const [existing] = await db
          .select({ id: summarizedGuardrail.id, expiresAt: summarizedGuardrail.expiresAt })
          .from(summarizedGuardrail)
          .where(and(eq(summarizedGuardrail.stackId, pair.stackId), eq(summarizedGuardrail.layerId, pair.layerId)))
          .limit(1);
        if (mode === "empty") return !existing;
        return !existing || (existing.expiresAt !== null && existing.expiresAt < now);
      })();
      if (shouldGenerate) layerSlugsToProcess.push(layerSlug);
    }

    if (layerSlugsToProcess.length === 0) continue;

    try {
      const stackResults = await runSummarizerForStack(stackSlug, layerSlugsToProcess, "all", undefined, mode === "all");
      for (const r of stackResults) {
        if (r.ruleCount > 0) generated++;
      }
    } catch (e) {
      errors.push(`${stackSlug}: ${e instanceof Error ? e.message : String(e)}`);
    }

    await new Promise((r) => setTimeout(r, 300));
  }

  return { generated, skipped: pairs.length - generated - errors.length, errors };
}
