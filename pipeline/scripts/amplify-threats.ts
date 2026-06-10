import "../lib/load-env";

import { and, eq, exists, isNull, sql } from "drizzle-orm";

import { db, pool, stack, threat, threatStack } from "../lib/db";
import { createLLMClient, getModelForTask } from "../lib/summarizer/llm-client";

// ── Client setup ─────────────────────────────────────────────────────────────
// Supports both Anthropic direct and AWS Bedrock (set LLM_PROVIDER=bedrock).

const MODEL  = process.env.AMPLIFY_MODEL ?? getModelForTask("threat_amplification");
const client = createLLMClient();

// ── Config ────────────────────────────────────────────────────────────────────
const BATCH_SIZE   = parseInt(process.env.BATCH_SIZE ?? "50");
const STACK_FILTER = process.env.STACK_FILTER;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

// ── Tool schema ───────────────────────────────────────────────────────────────
const amplifyTool = {
  name: "write_threat_guardrail",
  description: "Write the guardrail content atoms for one security threat",
  input_schema: {
    type: "object" as const,
    properties: {
      patternLines: {
        type: "array",
        items: { type: "string" },
        description:
          "2–4 ALWAYS/NEVER statements specific to this vulnerability's attack vector. " +
          "Each line MUST start with ALWAYS or NEVER (uppercase). " +
          "Never mention dependency versions, package names, or upgrade instructions.",
        minItems: 1,
        maxItems: 4,
      },
      ruleContext: {
        type: "string",
        description:
          "One sentence, plain English, ≤120 characters, no markdown. " +
          "Describes the real-world risk a developer needs to understand about this specific CVE.",
      },
    },
    required: ["patternLines", "ruleContext"],
  },
};

// ── System prompts ────────────────────────────────────────────────────────────
// We keep two prompt variants — one for owasp_web threats (the default) and one
// for owasp_llm threats (LangChain / LlamaIndex / transformers / vLLM CVEs).
// Selection happens in amplifyThreat() based on threat.family.
const SYSTEM_PROMPT_WEB = `You are a security guardrail writer for developer IDE rules (Cursor, Claude Code, Windsurf).
You produce concise, actionable content for pattern-level security rules.

PATTERN LINES rules:
- 2 to 4 lines, each starting with ALWAYS or NEVER (uppercase)
- Specific to this vulnerability's attack vector — not generic security advice
- About code structure and safe API usage only
- Never mention package names, version numbers, or upgrade instructions
- Good: "NEVER rely on pathname-only middleware checks for authorization."
- Good: "ALWAYS validate outbound request hostnames against an explicit allowlist."
- Bad: "ALWAYS follow vendor guidance" (too generic)
- Bad: "ALWAYS upgrade to version 9.0.0" (mentions versions)

RULE CONTEXT rules:
- Exactly one sentence, ≤120 characters, no markdown, no backticks
- Names the specific real-world risk of this CVE
- Good: "Redirect handling can forward Authorization and cookie headers to untrusted origins."
- Bad: "This vulnerability affects node-fetch versions before 2.6.7." (describes the patch, not the risk)`;

const SYSTEM_PROMPT_LLM = `You are a security guardrail writer for developer IDE rules (Cursor, Claude Code, Windsurf).
You produce concise, actionable content for pattern-level security rules targeting AI / LLM applications
(LangChain, LlamaIndex, Hugging Face transformers, vLLM, llama-cpp-python, Ollama, agent frameworks).
Frame guidance against the OWASP LLM Top 10 categories (LLM01 Prompt Injection, LLM02 Insecure Output
Handling, LLM03 Training Data Poisoning, LLM04 Model DoS, LLM05 Supply Chain, LLM06 Sensitive Info
Disclosure, LLM07 Insecure Plugin Design, LLM08 Excessive Agency, LLM09 Overreliance, LLM10 Model Theft).

PATTERN LINES rules:
- 2 to 4 lines, each starting with ALWAYS or NEVER (uppercase)
- Specific to this LLM-application attack vector — not generic security advice
- About prompt construction, tool/agent boundaries, output handling, model loading, or retrieval safety
- Never mention package names, version numbers, or upgrade instructions
- Good: "NEVER concatenate untrusted retrieval-augmented context directly into the system prompt."
- Good: "ALWAYS bound agent tools to an explicit allowlist of callable functions."
- Good: "NEVER deserialize model checkpoints from untrusted sources without integrity verification."
- Bad: "ALWAYS sanitize input" (generic — say HOW for the LLM context)
- Bad: "ALWAYS upgrade langchain to 0.1.0" (mentions versions)

RULE CONTEXT rules:
- Exactly one sentence, ≤120 characters, no markdown, no backticks
- Names the specific real-world LLM risk this CVE creates
- Good: "Tool-calling agent permits arbitrary URL fetch via crafted prompts, enabling SSRF to internal services."
- Bad: "This vulnerability affects langchain versions before 0.0.330." (describes patch, not risk)`;

// ── Types ─────────────────────────────────────────────────────────────────────
interface AmplifyResult {
  patternLines: string[];
  ruleContext: string;
}

// ── Per-threat amplification ──────────────────────────────────────────────────
async function amplifyThreat(
  t: typeof threat.$inferSelect
): Promise<AmplifyResult | null> {
  const owaspRefs = (t.owaspRefs as string[] | null) ?? [];
  const products  = t.affectedProducts as Array<{ name?: string; ecosystem?: string }> | null;
  const pkgNames  = products?.map(p => p.name).filter(Boolean).join(", ") ?? "unknown";

  const userPrompt = [
    `Threat ID: ${t.publicId}`,
    `Name: ${t.name}`,
    `Description: ${t.description?.slice(0, 600) ?? "Not available"}`,
    `OWASP categories: ${owaspRefs.join(", ") || "unknown"}`,
    `Affected packages: ${pkgNames}`,
    "",
    "Write the guardrail content for this threat.",
  ].join("\n");

  // Pick the prompt that matches the threat family — LLM threats need
  // OWASP-LLM-shaped guardrails, web threats need OWASP-Web-shaped ones.
  const systemText = t.family === "owasp_llm"
    ? SYSTEM_PROMPT_LLM
    : SYSTEM_PROMPT_WEB;

  try {
    const response = await client.messages.create({
      model:      MODEL,
      max_tokens: 400,
      system: [
        {
          type:          "text",
          text:          systemText,
          cache_control: { type: "ephemeral" },
        },
      ],
      tools:       [amplifyTool],
      tool_choice: { type: "tool", name: "write_threat_guardrail" },
      messages:    [{ role: "user", content: userPrompt }],
    });

    const { usage } = response;
    const cacheCreated = (usage as { cache_creation_input_tokens?: number }).cache_creation_input_tokens ?? 0;
    const cacheRead    = (usage as { cache_read_input_tokens?: number }).cache_read_input_tokens    ?? 0;
    if (cacheCreated) process.stdout.write(` [cache warmed: ${cacheCreated}t]`);
    if (cacheRead)    process.stdout.write(` [cache hit: ${cacheRead}t]`);

    const toolUse = response.content.find(b => b.type === "tool_use");
    if (!toolUse || toolUse.type !== "tool_use") return null;

    const input = toolUse.input as AmplifyResult;
    if (!input.patternLines?.length || !input.ruleContext?.trim()) return null;
    return { patternLines: input.patternLines, ruleContext: input.ruleContext.trim() };
  } catch (e) {
    console.error(`  ✗ ${t.publicId}:`, (e as Error).message);
    return null;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`Model: ${MODEL}`);
  if (STACK_FILTER) console.log(`Stack filter: ${STACK_FILTER}`);
  console.log();

  const stackCondition = STACK_FILTER
    ? exists(
        db.select({ one: sql`1` })
          .from(threatStack)
          .innerJoin(stack, eq(stack.id, threatStack.stackId))
          .where(and(
            eq(threatStack.threatId, threat.publicId),
            eq(stack.slug, STACK_FILTER)
          ))
      )
    : undefined;

  const rows = await db
    .select()
    .from(threat)
    .where(stackCondition ? and(isNull(threat.aiAmplification), stackCondition) : isNull(threat.aiAmplification))
    .limit(BATCH_SIZE);

  if (rows.length === 0) {
    console.log("No threats need amplification.");
    return;
  }

  console.log(`Amplifying ${rows.length} threats...`);
  let succeeded = 0;

  for (const t of rows) {
    process.stdout.write(`  ${t.publicId} ... `);
    const result = await amplifyThreat(t);
    if (!result) {
      console.log("skipped");
      continue;
    }

    await db
      .update(threat)
      .set({
        aiAmplification: JSON.stringify({
          patternLines: result.patternLines,
          ruleContext:  result.ruleContext,
          generatedAt:  new Date().toISOString(),
          model:        MODEL,
        }),
      })
      .where(eq(threat.publicId, t.publicId));

    console.log("✓");
    succeeded++;
    await sleep(300);
  }

  console.log(`\nDone: ${succeeded}/${rows.length} threats amplified.`);
  if (succeeded < rows.length) {
    console.log(`Tip: run again to retry the ${rows.length - succeeded} skipped threats.`);
  }
}

main()
  .catch(err => {
    console.error("Fatal:", err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
