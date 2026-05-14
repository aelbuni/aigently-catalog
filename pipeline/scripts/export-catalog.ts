import "../lib/load-env";

import fs from "fs";
import path from "path";

import { eq } from "drizzle-orm";

import {
  db,
  pool,
  rule,
  ruleStack,
  ruleThreatMap,
  stack,
  threat,
  threatStack,
} from "../lib/db";

const OUT_DIR = path.resolve(__dirname, "../../../packages/catalog-data");

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

  const threatStackMap = new Map<string, string[]>();
  for (const row of threatStackRows) {
    const slugs = threatStackMap.get(row.threatId) ?? [];
    slugs.push(row.stackSlug);
    threatStackMap.set(row.threatId, slugs);
  }

  const threats = threatRows.map(t => ({
    ...t,
    stacks: threatStackMap.get(t.publicId) ?? [],
  }));

  // ── Rules ──────────────────────────────────────────────────────────────────
  const ruleRows = await db
    .select({
      id:          rule.id,
      slug:        rule.slug,
      name:        rule.name,
      description: rule.description,
      version:     rule.version,
      bodyMdx:     rule.bodyMdx,
      summaryMdx:  rule.summaryMdx,
    })
    .from(rule);

  const ruleStackRows = await db
    .select({ ruleId: ruleStack.ruleId, stackSlug: stack.slug })
    .from(ruleStack)
    .innerJoin(stack, eq(ruleStack.stackId, stack.id));

  const ruleThreatRows = await db
    .select({ ruleId: ruleThreatMap.ruleId, threatId: ruleThreatMap.threatId })
    .from(ruleThreatMap);

  const ruleStackMap   = new Map<string, string[]>();
  const ruleThreatMapJ = new Map<string, string[]>();

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

  const rules = ruleRows.map(r => ({
    ...r,
    stacks:    ruleStackMap.get(r.id)    ?? [],
    threatIds: ruleThreatMapJ.get(r.id) ?? [],
  }));

  // ── Manifest ───────────────────────────────────────────────────────────────
  const manifest = {
    version:     "1.0.0",
    generatedAt: new Date().toISOString(),
    counts: {
      threats: threats.length,
      rules:   rules.length,
      stacks:  stacks.length,
    },
  };

  // ── Write files ────────────────────────────────────────────────────────────
  write("manifest.json", manifest);
  write("stacks.json",   stacks);
  write("threats.json",  threats);
  write("rules.json",    rules);

  console.log(`\nDone: ${threats.length} threats, ${rules.length} rules, ${stacks.length} stacks.`);
}

main()
  .catch(err => {
    console.error("Export failed:", err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
