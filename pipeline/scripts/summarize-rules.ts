import "../lib/load-env";

import Anthropic from "@anthropic-ai/sdk";
import { and, eq, isNull, like } from "drizzle-orm";

import { db, pool, rule, ruleStack, ruleThreatMap, stack, threat } from "../lib/db";

// ── Client setup ──────────────────────────────────────────────────────────────
// Reads ANTHROPIC_API_KEY from env automatically.
const MODEL      = "claude-sonnet-4-6";
const FORCE      = process.env.FORCE === "1";
const STACK_SLUG =
  process.env.STACK_SLUG ??
  (process.argv.includes("--stack")
    ? process.argv[process.argv.indexOf("--stack") + 1]
    : null) ??
  null;

const client = new Anthropic();

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

// ── Types ─────────────────────────────────────────────────────────────────────
interface SummaryCluster {
  title: string;
  cveIds: string[];
  riskSummary: string;
  patternLines: string[];
}

interface CrossCuttingPattern {
  patternLine: string;
  rationale: string;
}

interface RuleSummaryOutput {
  executivePreamble: string;
  clusters: SummaryCluster[];
  crossCuttingPatterns: CrossCuttingPattern[];
}

// ── Tool schema ───────────────────────────────────────────────────────────────
const summarizeTool = {
  name: "write_rule_summary",
  description:
    "Write the expert-synthesized CVE summary for one technology stack's security rule. " +
    "Clusters CVEs by attack-vector theme and produces actionable guardrail patterns.",
  input_schema: {
    type: "object" as const,
    properties: {
      executivePreamble: {
        type: "string",
        description:
          "2-sentence stack-level preamble. Sentence 1: dominant attack surface area. " +
          "Sentence 2: the recurring coding mistake that enables these CVEs. " +
          "Plain English, no markdown, ≤200 chars total.",
      },
      clusters: {
        type: "array",
        description: "2–5 attack-vector theme clusters covering all input CVEs exactly once each.",
        minItems: 2,
        maxItems: 5,
        items: {
          type: "object",
          required: ["title", "cveIds", "riskSummary", "patternLines"],
          properties: {
            title: {
              type: "string",
              description:
                "Short title naming the shared attack vector, NOT the OWASP label. " +
                "Example: 'Authorization Bypass via Middleware Trust'.",
            },
            cveIds: {
              type: "array",
              items: { type: "string" },
              description: "All CVE/advisory IDs in this cluster. Each ID appears in exactly one cluster.",
              minItems: 1,
            },
            riskSummary: {
              type: "string",
              description:
                "One sentence, plain English, ≤150 chars. Describes the shared real-world risk. " +
                "Must contain 'ACTIVELY EXPLOITED' if any CVE in this cluster is actively exploited.",
            },
            patternLines: {
              type: "array",
              items: { type: "string" },
              description:
                "3–6 ALWAYS/NEVER lines specific to this cluster's shared attack vector. " +
                "Each line starts with ALWAYS or NEVER. No version numbers. No upgrade instructions.",
              minItems: 3,
              maxItems: 6,
            },
          },
        },
      },
      crossCuttingPatterns: {
        type: "array",
        description: "2–4 stack-wide ALWAYS/NEVER lines not already covered by any cluster.",
        minItems: 2,
        maxItems: 4,
        items: {
          type: "object",
          required: ["patternLine", "rationale"],
          properties: {
            patternLine: {
              type: "string",
              description: "One ALWAYS or NEVER line that applies across all clusters.",
            },
            rationale: {
              type: "string",
              description: "≤80 chars. Which clusters it unifies or transcends.",
            },
          },
        },
      },
    },
    required: ["executivePreamble", "clusters", "crossCuttingPatterns"],
  },
};

// ── System prompt ─────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are a Principal Security Architect writing security guardrail summaries for developer AI coding assistants (Cursor, Claude Code, Windsurf, Cline, GitHub Copilot).

Your audience is a software developer reading a rule in their IDE. The rule will be injected into the AI assistant's context and must guide the AI to suggest safe code patterns. Your output directly controls what that AI tells the developer.

OBJECTIVE
Synthesize a set of CVE-level advisories for one technology stack into a structured, clustered summary that:
1. Groups CVEs by ATTACK-VECTOR THEME — the shared exploitation mechanism or trust-boundary pattern — NOT by OWASP label alone.
2. Produces cluster-level guardrails more actionable than any single CVE's advice.
3. Surfaces cross-stack patterns that hold regardless of which specific CVE fires.

CLUSTERING RULES
- A theme is defined by HOW the attacker exploits code, not WHAT OWASP calls it.
  Good theme names:
    "Authorization Bypass via Middleware Trust"
    "Header-Based SSRF and Credential Forwarding"
    "Prototype Pollution Gadget Chains"
    "ReDoS via Unbounded Regex on User Input"
    "Server Component Denial of Service"
- CVEs that share the same exploitation mechanism belong in the same cluster even if they carry different OWASP tags.
- Every CVE in the input MUST appear in exactly one cluster.
- Aim for 2–4 clusters; use up to 5 only if attack surfaces are truly distinct.

EXECUTIVE PREAMBLE
- Exactly 2 sentences. Sentence 1: dominant attack surface. Sentence 2: the coding mistake that repeatedly enables these CVEs.
- Plain English, no markdown, ≤200 characters total.

CLUSTER PATTERN LINES
- 3 to 6 lines per cluster, each starting with ALWAYS or NEVER (uppercase).
- Must be specific to the shared attack vector — NOT generic security advice.
- Good: "NEVER rely on the Host header in Server Actions to determine the redirect origin."
- Good: "ALWAYS treat __proto__, constructor, and prototype as injection vectors in any object merge."
- Bad: "ALWAYS follow security best practices." (too generic)
- Bad: "NEVER use lodash < 4.17.21." (version reference)
- No two clusters may share an identical or near-identical ALWAYS/NEVER line.

CROSS-CUTTING PATTERNS
- 2 to 4 lines, each starting with ALWAYS or NEVER.
- Must apply to the entire stack regardless of which cluster fires.
- Must NOT repeat or paraphrase any cluster's pattern lines.

ACTIVELY EXPLOITED FLAG
- If any CVE in a cluster is marked "Actively Exploited: YES" in the input, the riskSummary for that cluster MUST contain the exact phrase "ACTIVELY EXPLOITED".

NEGATIVE CONSTRAINTS (enforce strictly)
- NEVER mention version numbers.
- NEVER say "update the package", "upgrade to", "apply the patch", or any dependency management instruction.
- NEVER write "ALWAYS follow vendor guidance" or equivalent platitudes.
- NEVER repeat the same ALWAYS/NEVER line across clusters or cross-cutting patterns.
- NEVER use markdown headings, bold, or backticks in riskSummary or executivePreamble.
- NEVER write a riskSummary that describes the patch — describe the real-world risk.`;

// ── Prompt builder ────────────────────────────────────────────────────────────
function buildUserPrompt(
  stackName: string,
  stackSlug: string,
  threats: (typeof threat.$inferSelect)[]
): string {
  const sevOrder = (s: string | null) =>
    s === "critical" ? 0 : s === "high" ? 1 : s === "medium" ? 2 : 3;
  const sorted = [...threats].sort((a, b) => sevOrder(a.severity) - sevOrder(b.severity));

  const threatList = sorted.map(t => {
    const id = (t.cveId ?? t.publicId).trim();
    const owasp = ((t.owaspRefs as string[] | null) ?? []).join(", ") || "unclassified";
    const exploited = t.isActivelyExploited ? "YES — MARK THIS CLUSTER" : "no";
    const desc = (t.description ?? "Not available").slice(0, 400);
    return [
      `ID: ${id}`,
      `Name: ${t.name}`,
      `OWASP: ${owasp}`,
      `Severity: ${t.severity}`,
      `Actively Exploited: ${exploited}`,
      `Attack description: ${desc}`,
    ].join("\n");
  }).join("\n\n");

  return [
    `Stack: ${stackName} (${stackSlug})`,
    `Total CVEs/advisories: ${threats.length}`,
    "",
    "--- THREAT LIST ---",
    threatList,
    "--- END THREAT LIST ---",
    "",
    `Synthesize the above ${threats.length} threats into a structured summary using the write_rule_summary tool.`,
    "Cluster by attack-vector theme (the shared exploitation mechanism), not by OWASP category.",
    "Every threat ID above MUST appear in exactly one cluster.",
  ].join("\n");
}

// ── Markdown renderer ─────────────────────────────────────────────────────────
function renderSummaryToMarkdown(output: RuleSummaryOutput, stackName: string): string {
  const lines: string[] = [
    "## AI Security Summary",
    "",
    output.executivePreamble,
    "",
  ];

  for (const cluster of output.clusters) {
    lines.push(`### ${cluster.title}`);
    lines.push(`**Covers:** ${cluster.cveIds.join(" · ")}`);
    lines.push(`**Risk:** ${cluster.riskSummary}`);
    lines.push("");
    for (const p of cluster.patternLines) lines.push(`- ${p}`);
    lines.push("");
  }

  lines.push("---");
  lines.push(`**Cross-cutting patterns (all ${stackName} projects)**`);
  lines.push("");
  for (const p of output.crossCuttingPatterns) lines.push(`- ${p.patternLine}`);

  return lines.join("\n");
}

// ── Per-rule summarization ────────────────────────────────────────────────────
async function summarizeRule(
  ruleId: string,
  ruleSlug: string,
  stackName: string,
  stackSlug: string,
  threats: (typeof threat.$inferSelect)[]
): Promise<string | null> {
  if (threats.length === 0) {
    console.log("  (no linked threats, skipping)");
    return null;
  }

  const userPrompt = buildUserPrompt(stackName, stackSlug, threats);

  try {
    const response = await client.messages.create({
      model:       MODEL,
      max_tokens:  4096,
      system:      SYSTEM_PROMPT,
      tools:       [summarizeTool],
      tool_choice: { type: "tool", name: "write_rule_summary" },
      messages:    [{ role: "user", content: userPrompt }],
    });

    const toolUse = response.content.find(b => b.type === "tool_use");
    if (!toolUse || toolUse.type !== "tool_use") {
      const stopReason = response.stop_reason;
      const textBlock = response.content.find(b => b.type === "text");
      console.error(
        `  ✗ ${ruleSlug}: no tool_use block in response (stop_reason=${stopReason})` +
        (textBlock && textBlock.type === "text" ? ` — model text: ${textBlock.text.slice(0, 200)}` : "")
      );
      return null;
    }

    const output = toolUse.input as RuleSummaryOutput;
    if (!output.executivePreamble?.trim() || !output.clusters?.length) {
      console.error(
        `  ✗ ${ruleSlug}: tool output missing required fields` +
        ` — stop_reason=${response.stop_reason}` +
        ` preamble_len=${output.executivePreamble?.length ?? 0}` +
        ` clusters=${output.clusters?.length ?? 0}`
      );
      return null;
    }

    return renderSummaryToMarkdown(output, stackName);
  } catch (e) {
    const err = e as Error & { status?: number; error?: unknown };
    console.error(`  ✗ ${ruleSlug}: ${err.message}`);
    if (err.status) console.error(`    HTTP status: ${err.status}`);
    if (err.error) console.error(`    API error:`, JSON.stringify(err.error));
    return null;
  }
}

function computeStrengthScore(r: { certified: boolean; bodyMdx?: string | null; lineCount?: number | null }): number {
  const doNot     = /DO NOT|NEVER|AVOID/i.test(r.bodyMdx ?? "") ? 10 : 0;
  const cert      = r.certified ? 20 : 0;
  const lineScore = Math.min(Math.floor((r.lineCount ?? 0) / 5), 20);
  return Math.min(doNot + cert + lineScore + 10, 100);
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`Model: ${MODEL}`);
  if (STACK_SLUG) console.log(`Filter: stack = ${STACK_SLUG}`);
  if (FORCE) console.log("Mode: FORCE (overwrite existing summaries)");
  console.log();

  // Load patterns rules (not deps rules)
  const conditions = [like(rule.slug, "%-security-patterns-v1")];
  if (!FORCE) conditions.push(isNull(rule.summaryMdx));

  const rules = await db
    .select({ id: rule.id, slug: rule.slug, certified: rule.certified, bodyMdx: rule.bodyMdx, lineCount: rule.lineCount })
    .from(rule)
    .where(and(...conditions));

  if (rules.length === 0) {
    console.log("No rules need summarization. Run with FORCE=1 to overwrite existing summaries.");
    return;
  }

  // Filter by STACK_SLUG if provided
  const targetRules = STACK_SLUG
    ? rules.filter(r => r.slug.startsWith(`${STACK_SLUG}-`))
    : rules;

  if (targetRules.length === 0) {
    console.log(`No rules found for stack: ${STACK_SLUG}`);
    return;
  }

  console.log(`Summarizing ${targetRules.length} rule(s)...`);
  let succeeded = 0;

  for (const r of targetRules) {
    process.stdout.write(`  ${r.slug} ... `);

    // Load the stack this rule belongs to
    const [stackRow] = await db
      .select({ slug: stack.slug, name: stack.name })
      .from(ruleStack)
      .innerJoin(stack, eq(ruleStack.stackId, stack.id))
      .where(eq(ruleStack.ruleId, r.id))
      .limit(1);

    if (!stackRow) {
      console.log("(no stack found, skipping)");
      continue;
    }

    // Load all threats linked to this rule
    const threatRows = await db
      .select({
        publicId: threat.publicId,
        cveId: threat.cveId,
        name: threat.name,
        severity: threat.severity,
        description: threat.description,
        owaspRefs: threat.owaspRefs,
        isActivelyExploited: threat.isActivelyExploited,
      })
      .from(ruleThreatMap)
      .innerJoin(threat, eq(ruleThreatMap.threatId, threat.publicId))
      .where(eq(ruleThreatMap.ruleId, r.id));

    const rendered = await summarizeRule(
      r.id,
      r.slug,
      stackRow.name,
      stackRow.slug,
      threatRows as (typeof threat.$inferSelect)[]
    );

    if (!rendered) {
      console.log("skipped");
      continue;
    }

    const strengthScore = computeStrengthScore(r);
    await db
      .update(rule)
      .set({ summaryMdx: rendered, strengthScore, updatedAt: new Date() })
      .where(eq(rule.id, r.id));

    console.log("✓");
    succeeded++;
    await sleep(500);
  }

  console.log(`\nDone: ${succeeded}/${targetRules.length} rules summarized.`);
  if (succeeded < targetRules.length) {
    console.log(`Tip: run again to retry the ${targetRules.length - succeeded} skipped rule(s).`);
  }
}

main()
  .catch(err => {
    console.error("Fatal:", err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
