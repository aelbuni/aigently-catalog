import "../lib/load-env";

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { eq } from "drizzle-orm";

import {
  db,
  ide,
  layer,
  pool,
  rule,
  ruleIde,
  ruleLayerMap,
  ruleStack,
  ruleThreatMap,
  stack,
  summarizedGuardrail,
  threat,
  threatLayer,
  threatStack,
} from "../lib/db";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OUT_DIR = path.resolve(__dirname, "../../packages/catalog-data");

function write(filename: string, data: unknown): void {
  fs.writeFileSync(path.join(OUT_DIR, filename), JSON.stringify(data, null, 2) + "\n");
  console.log(`  ✓ ${filename}`);
}

async function main() {
  console.log("Exporting catalog to JSON...");

  // ── Stacks ─────────────────────────────────────────────────────────────────
  const stacks = await db
    .select({
      slug:          stack.slug,
      name:          stack.name,
      ecosystem:     stack.ecosystem,
      catalogStatus: stack.catalogStatus,
      securityGrade: stack.securityGrade,
      sortOrder:     stack.sortOrder,
    })
    .from(stack)
    .orderBy(stack.sortOrder);

  // ── Threats ────────────────────────────────────────────────────────────────
  const threatRows = await db
    .select({
      publicId:            threat.publicId,
      cveId:               threat.cveId,
      source:              threat.source,
      sourceUrl:           threat.sourceUrl,
      family:              threat.family,
      name:                threat.name,
      description:         threat.description,
      severity:            threat.severity,
      owaspRefs:           threat.owaspRefs,
      isActivelyExploited: threat.isActivelyExploited,
      affectedProducts:    threat.affectedProducts,
      aiAmplification:     threat.aiAmplification,
      publishedAt:         threat.publishedAt,
      syncedAt:            threat.syncedAt,
    })
    .from(threat);

  // Build stack slug list per threat
  const threatStackRows = await db
    .select({
      threatId:  threatStack.threatId,
      stackSlug: stack.slug,
      severity:  threatStack.severity,
    })
    .from(threatStack)
    .innerJoin(stack, eq(threatStack.stackId, stack.id));

  const threatLayerRows = await db
    .select({ threatId: threatLayer.threatId, layerSlug: layer.slug })
    .from(threatLayer)
    .innerJoin(layer, eq(threatLayer.layerId, layer.id));

  const threatStackMap = new Map<string, string[]>();
  const threatLayerMapJ = new Map<string, string[]>();

  for (const row of threatStackRows) {
    const slugs = threatStackMap.get(row.threatId) ?? [];
    slugs.push(row.stackSlug);
    threatStackMap.set(row.threatId, slugs);
  }
  for (const row of threatLayerRows) {
    const slugs = threatLayerMapJ.get(row.threatId) ?? [];
    slugs.push(row.layerSlug);
    threatLayerMapJ.set(row.threatId, slugs);
  }

  const threats = threatRows.map(t => ({
    ...t,
    stacks:  threatStackMap.get(t.publicId)  ?? [],
    layers:  threatLayerMapJ.get(t.publicId) ?? [],
  }));

  // ── Rules ──────────────────────────────────────────────────────────────────
  const ruleRows = await db
    .select({
      id:            rule.id,
      slug:          rule.slug,
      name:          rule.name,
      description:   rule.description,
      version:       rule.version,
      ruleType:      rule.ruleType,
      strengthScore: rule.strengthScore,
      bodyMdx:       rule.bodyMdx,
      summaryMdx:    rule.summaryMdx,
    })
    .from(rule);

  const ruleStackRows = await db
    .select({ ruleId: ruleStack.ruleId, stackSlug: stack.slug })
    .from(ruleStack)
    .innerJoin(stack, eq(ruleStack.stackId, stack.id));

  const ruleThreatRows = await db
    .select({ ruleId: ruleThreatMap.ruleId, threatId: ruleThreatMap.threatId })
    .from(ruleThreatMap);

  const ruleLayerRows = await db
    .select({ ruleId: ruleLayerMap.ruleId, layerSlug: layer.slug })
    .from(ruleLayerMap)
    .innerJoin(layer, eq(ruleLayerMap.layerId, layer.id));

  const ruleIdeRows = await db
    .select({ ruleId: ruleIde.ruleId, ideSlug: ide.slug })
    .from(ruleIde)
    .innerJoin(ide, eq(ruleIde.ideId, ide.id));

  const ruleStackMap   = new Map<string, string[]>();
  const ruleThreatMapJ = new Map<string, string[]>();
  const ruleLayerMapJ  = new Map<string, string[]>();
  const ruleIdeMapJ    = new Map<string, string[]>();

  for (const row of ruleStackRows) {
    const slugs = ruleStackMap.get(row.ruleId) ?? [];
    slugs.push(row.stackSlug);
    ruleStackMap.set(row.ruleId, slugs);
  }
  for (const row of ruleThreatRows) {
    const ids = ruleThreatMapJ.get(row.ruleId) ?? [];
    ids.push(row.threatId);
    ruleThreatMapJ.set(row.ruleId, ids);
  }
  for (const row of ruleLayerRows) {
    const slugs = ruleLayerMapJ.get(row.ruleId) ?? [];
    slugs.push(row.layerSlug);
    ruleLayerMapJ.set(row.ruleId, slugs);
  }
  for (const row of ruleIdeRows) {
    const slugs = ruleIdeMapJ.get(row.ruleId) ?? [];
    slugs.push(row.ideSlug);
    ruleIdeMapJ.set(row.ruleId, slugs);
  }

  const rules = ruleRows.map(r => ({
    ...r,
    stacks:    ruleStackMap.get(r.id)   ?? [],
    layers:    ruleLayerMapJ.get(r.id)  ?? [],
    ides:      ruleIdeMapJ.get(r.id)    ?? [],  // empty = applies to all IDEs
    threatIds: ruleThreatMapJ.get(r.id) ?? [],
  }));

  // ── Guardrails ─────────────────────────────────────────────────────────────
  const guardrailRows = await db
    .select({
      stackSlug:         stack.slug,
      layerSlug:         layer.slug,
      content:           summarizedGuardrail.content,
      qualityScore:      summarizedGuardrail.qualityScore,
      scoreOverride:     summarizedGuardrail.scoreOverride,
      conflictCount:     summarizedGuardrail.conflictCount,
      sourceRuleIds:     summarizedGuardrail.sourceRuleIds,
      summarizerVersion: summarizedGuardrail.summarizerVersion,
      generatedAt:       summarizedGuardrail.generatedAt,
      cacheKey:          summarizedGuardrail.cacheKey,
    })
    .from(summarizedGuardrail)
    .innerJoin(stack, eq(summarizedGuardrail.stackId, stack.id))
    .innerJoin(layer, eq(summarizedGuardrail.layerId, layer.id));

  // ── Manifest ───────────────────────────────────────────────────────────────
  const manifest = {
    version:     "1.0.0",
    generatedAt: new Date().toISOString(),
    counts: {
      threats:    threats.length,
      rules:      rules.length,
      stacks:     stacks.length,
      guardrails: guardrailRows.length,
    },
  };

  // ── Write files ────────────────────────────────────────────────────────────
  write("manifest.json",   manifest);
  write("stacks.json",     stacks);
  write("threats.json",    threats);
  write("rules.json",      rules);
  write("guardrails.json", guardrailRows);

  console.log(`\nDone: ${threats.length} threats, ${rules.length} rules, ${stacks.length} stacks, ${guardrailRows.length} guardrails.`);
}

main()
  .catch(err => {
    console.error("Export failed:", err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
