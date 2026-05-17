---
name: pipeline-run
description: Run the aigently-catalog pipeline for a single stack and analyze output alignment with the data model. Pass a stack slug as argument (e.g. /pipeline-run nextjs). Available slugs: nextjs, express, fastapi, nestjs, nuxt, react-spa.
---

# Pipeline Run Skill

Run the full aigently-catalog pipeline for a single stack and analyze the results.

## Step 1 — Resolve the stack slug

If the user passed a slug as an argument (e.g. `/pipeline-run nextjs`), use that directly.

If no slug was given, ask the user which stack to run. Valid slugs:
- `nextjs`, `express`, `fastapi`, `nestjs`, `nuxt`, `react-spa`

Set `SLUG=<chosen slug>` for all steps below.

## Step 2 — Run each pipeline phase

Run these commands in order. Stop and report if any phase exits non-zero.

All commands run from `/Users/aelbuni/Projects/aelbuni/aigently-catalog`.

```bash
# Phase 1: Sync CVE threats for this stack only
STACK_FILTER=$SLUG npm run sync:threats -w @aigently/pipeline

# Phase 2: Amplify unamplified threats linked to this stack
STACK_FILTER=$SLUG npm run amplify:threats -w @aigently/pipeline

# Phase 3: Summarize rules for this stack
STACK_SLUG=$SLUG npm run summarize:rules -w @aigently/pipeline

# Phase 4: Synthesize guardrails for this stack (force regenerate)
STACK_SLUG=$SLUG SYNTHESIZE_MODE=all npm run synthesize:guardrails -w @aigently/pipeline

# Phase 5: Export all JSON (includes guardrails.json)
npm run export:catalog -w @aigently/pipeline
```

After each phase, print a one-line status: phase name, exit code, and any key counts from stdout (e.g. "Phase 1: ✓ — 47 threats synced").

## Step 3 — Analyze output

Run this analysis against the exported JSON files:

```bash
cd /Users/aelbuni/Projects/aelbuni/aigently-catalog && node --input-type=module <<EOF
import { readFileSync } from "fs";

const SLUG = "$SLUG";
const threats  = JSON.parse(readFileSync("packages/catalog-data/threats.json",    "utf8"));
const rules    = JSON.parse(readFileSync("packages/catalog-data/rules.json",      "utf8"));
const guards   = JSON.parse(readFileSync("packages/catalog-data/guardrails.json", "utf8"));
const manifest = JSON.parse(readFileSync("packages/catalog-data/manifest.json",   "utf8"));

const stackThreats = threats.filter(t => t.stacks.includes(SLUG));
const stackRules   = rules.filter(r => r.stacks.includes(SLUG));
const stackGuards  = guards.filter(g => g.stackSlug === SLUG);

const amplified    = stackThreats.filter(t => t.aiAmplification).length;
const withLayers   = stackRules.filter(r => r.layers?.length > 0).length;
const withSummary  = stackRules.filter(r => r.summaryMdx).length;
const withScore    = stackRules.filter(r => r.strengthScore > 0).length;

console.log(JSON.stringify({
  stack: SLUG,
  catalog: { generatedAt: manifest.generatedAt, totalThreats: manifest.counts.threats, totalGuardrails: manifest.counts.guardrails },
  threats: { total: stackThreats.length, amplified, amplifiedPct: stackThreats.length ? Math.round(amplified/stackThreats.length*100) : 0 },
  rules:   { total: stackRules.length, withLayers, withSummary, withScore },
  guardrails: stackGuards.map(g => ({
    layer:        g.layerSlug,
    qualityScore: g.qualityScore,
    sourceRules:  g.sourceRuleIds?.length ?? 0,
    contentLen:   g.content?.length ?? 0,
    contentPreview: g.content?.split("\\n").slice(0,3).join(" | "),
  })),
  issues: [
    ...stackRules.filter(r => !r.layers?.length).map(r => "rule missing layers: " + r.slug),
    ...stackRules.filter(r => !r.strengthScore).map(r => "rule strengthScore=0: " + r.slug),
    ...stackThreats.filter(t => !t.aiAmplification).map(t => "threat not amplified: " + t.publicId),
    ...stackThreats.filter(t => !t.layers?.length).map(t => "threat missing layer assignment: " + t.publicId),
  ].slice(0, 20),
}, null, 2));
EOF
```

## Step 4 — Report findings

Format and present the analysis results clearly:

1. **Header**: Stack name, pipeline run timestamp, total counts
2. **Threats**: total / amplified / amplification %, flag if < 80% amplified
3. **Rules**: total / with layers / with summary / with strengthScore, flag any missing
4. **Guardrails** table: one row per layer with quality score, source rule count, content length
5. **Data model issues**: list every issue found (missing layers, zero scores, unamplified threats)
6. **Overall verdict**: ALIGNED ✓ or ISSUES FOUND ✗ with summary of what needs fixing

If there are issues, suggest the exact fix (e.g. "Run `SYNTHESIZE_MODE=all` to regenerate guardrails" or "Run amplify:threats again — N threats still unamplified").
