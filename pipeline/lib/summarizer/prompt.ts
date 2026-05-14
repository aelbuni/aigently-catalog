import type { DirectiveAtom } from "./atoms.js";

type LayerInfo = { slug: string; name: string; concernStatement: string };
type StackInfo = { slug: string; name: string };

function unique<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

export function buildSummarizerPrompt(
  atoms: DirectiveAtom[],
  layers: LayerInfo[],
  stack: StackInfo,
  previousScore?: number,
): string {
  const layerNames = layers.map((l) => l.name).join(" + ");
  const concerns = layers.map((l) => l.concernStatement).join("; ");
  const sourceRuleIds = unique(atoms.map((a) => a.sourceRuleId));
  const allCwes = unique(atoms.flatMap((a) => a.cweRefs));
  const conflicted = atoms.filter((a) => a.conflictResolution === "conflict_resolved");

  return `You are a principal security engineer synthesizing guardrail rules for AI coding assistants.

STACK: ${stack.name}
LAYER(S): ${layerNames}
CONCERN: ${concerns}

You have been given ${atoms.length} directive atoms extracted from ${sourceRuleIds.length} community-contributed rules.

DIRECTIVE ATOMS:
${atoms.map((a) => `[${a.severity.toUpperCase()}] ${a.content} (Source: ${a.sourceRuleId}${a.cweRefs.length ? `, CWE: ${a.cweRefs.join(", ")}` : ""})`).join("\n")}

${conflicted.length > 0 ? `CONFLICTS RESOLVED:\n${conflicted.map((a) => `- "${a.content}" was chosen over conflicting variant (reason: higher severity)`).join("\n")}\n` : ""}YOUR TASK:
Write a single, unified guardrail rule for the ${layerNames} layer(s) of a ${stack.name} project.
Keep the guardrail to 400 words maximum.

Rules:
1. Write as direct instructions TO the AI coding assistant (imperative voice)
2. Cover all unique concerns — name the specific CWE-NNN or CVE each directive addresses, not just "injection"
3. Be specific — name exact functions, packages, patterns to avoid or prefer
4. Use WHEN/THEN structure for context-dependent directives
5. Open with a comment block:
   # aigently: ${stack.slug}-${layers.map((l) => l.slug).join("+")}-guardrails v1.0 [summarized]
   # Merged from ${sourceRuleIds.length} rules
   # Protects: ${allCwes.length ? allCwes.join(", ") : "multiple threat vectors"}
6. End with a DO NOT section listing the most dangerous patterns

Output the guardrail text only — no preamble, no markdown fencing, no explanation.${previousScore !== undefined && previousScore < 8 ? `

QUALITY FEEDBACK (previous score: ${previousScore}/10):
This guardrail needs improvement. Address the following before rewriting:
${previousScore <= 3 ? "- Content is too sparse — expand with specific WHEN/THEN patterns citing each CWE by number." : ""}
${atoms.filter((a) => a.conflictResolution === "conflict_resolved").length > 2 ? "- High conflict count — merge overlapping directives into one clear stance per topic." : ""}
${unique(atoms.map((a) => a.sourceRuleId)).length < 2 ? "- Thin coverage — ensure every atom's CWE is addressed with a named code pattern." : ""}
Target: 8/10 or higher. Write with specificity, completeness, and zero redundancy.` : ""}`.trim();
}

export const MULTI_LAYER_TOOL = {
  name: "produce_stack_guardrails",
  description: "Write one complete guardrail section per security layer for a single stack. Each section is stored and served independently.",
  input_schema: {
    type: "object" as const,
    properties: {
      guardrails: {
        type: "array",
        description: "One entry per layer that had directive atoms. Preserve the layer order from the prompt.",
        items: {
          type: "object",
          required: ["layerSlug", "content", "conflictCount"],
          properties: {
            layerSlug: {
              type: "string",
              description: "Exact slug from the === LAYER === header in the prompt.",
            },
            content: {
              type: "string",
              description: "Complete guardrail text for this layer (300-500 words). Imperative voice, starts with the # aigently comment block, ends with DO NOT section.",
            },
            conflictCount: {
              type: "number",
              description: "Number of conflict-resolved atoms in this layer (can be 0).",
            },
          },
        },
        minItems: 1,
      },
    },
    required: ["guardrails"],
  },
};

export type BatchLayerInput = {
  layer: LayerInfo;
  atoms: DirectiveAtom[];
  sourceRuleIds: string[];
};

export function buildMultiLayerBatchPrompt(
  layers: BatchLayerInput[],
  stack: StackInfo,
  previousScoresByLayer?: Record<string, number>,
): string {
  const layerSections = layers.map(({ layer, atoms, sourceRuleIds }) => {
    const allCwes = unique(atoms.flatMap((a) => a.cweRefs));
    const conflicted = atoms.filter((a) => a.conflictResolution === "conflict_resolved");
    const prevScore = previousScoresByLayer?.[layer.slug];

    const atomLines = atoms
      .map((a) => `[${a.severity.toUpperCase()}] ${a.content} (Source: ${a.sourceRuleId}${a.cweRefs.length ? `, CWE: ${a.cweRefs.join(", ")}` : ""})`)
      .join("\n");

    const conflictBlock = conflicted.length > 0
      ? `CONFLICTS RESOLVED (${conflicted.length}):\n${conflicted.map((a) => `- "${a.content}" chosen over conflicting variant (higher severity)`).join("\n")}\n`
      : "";

    const feedbackBlock = prevScore !== undefined && prevScore < 8
      ? [
          `QUALITY FEEDBACK (previous score: ${prevScore}/10):`,
          prevScore <= 3 ? `- Too sparse — expand with specific WHEN/THEN patterns citing each CWE.` : "",
          conflicted.length > 2 ? `- High conflict count — consolidate overlapping directives.` : "",
          sourceRuleIds.length < 2 ? `- Thin coverage — address every CWE with a named code pattern.` : "",
          `- Target 8/10. Prioritise specificity, completeness, zero redundancy.`,
        ].filter(Boolean).join("\n")
      : "";

    return [
      `=== LAYER: ${layer.name} | slug: ${layer.slug} ===`,
      `CONCERN: ${layer.concernStatement}`,
      `DIRECTIVE ATOMS: ${atoms.length} atoms from ${sourceRuleIds.length} rules | Protects: ${allCwes.length ? allCwes.join(", ") : "multiple threat vectors"}`,
      atomLines,
      conflictBlock,
      feedbackBlock,
      `Expected comment block header for this layer:`,
      `# aigently: ${stack.slug}-${layer.slug}-guardrails v1.0 [summarized]`,
      `# Merged from ${sourceRuleIds.length} rules | Protects: ${allCwes.length ? allCwes.join(", ") : "multiple threat vectors"}`,
    ].filter(Boolean).join("\n");
  });

  return `You are a principal security engineer synthesizing guardrail rules for AI coding assistants.

STACK: ${stack.name} (${stack.slug})
LAYERS TO PROCESS: ${layers.length}

You will produce one independent guardrail section per security layer below.
Each section will be stored and served to IDEs separately — do not cross-reference layers.
Keep each section to 300-500 words.

${layerSections.join("\n\n")}

YOUR TASK:
Call the produce_stack_guardrails tool with one entry per layer above.

Rules for every section:
1. Imperative voice — direct instructions TO the AI coding assistant
2. Name the specific CWE-NNN or CVE each directive addresses — not just "injection"
3. Be specific — name exact functions, packages, and patterns to avoid or prefer
4. Use WHEN/THEN for context-dependent directives
5. Open with the exact comment block header shown above for each layer
6. End with a DO NOT block listing the highest-severity patterns

Output ALL ${layers.length} layers using the tool. Do not skip any.`.trim();
}
