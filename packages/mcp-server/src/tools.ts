import {
  getStacks, getThreats, getRules, getGuardrails, getManifest,
  parseAmplification,
  type CatalogThreat, type CatalogRule,
} from "./catalog.js";
import { detectContext } from "./detect.js";
import { resolveLayersFromIntent } from "./intentResolver.js";

// ── Shared helpers ─────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function sevScore(s: string | null): number {
  return SEV_ORDER[s ?? "info"] ?? 5;
}

function scoreThreat(t: CatalogThreat, ruleIds: Set<string>, intentLower: string): number {
  let score = 0;
  if (ruleIds.has(t.publicId))    score += 3;
  if (t.isActivelyExploited)      score += 2;
  if (sevScore(t.severity) <= 1)  score += 2;
  const owasp = (t.owaspRefs ?? []).join(" ").toLowerCase();
  if (intentLower.includes("auth") && (owasp.includes("a02") || owasp.includes("a07"))) score += 1;
  if (intentLower.includes("inject") && owasp.includes("a03")) score += 1;
  if (intentLower.includes("xss") && owasp.includes("a03"))    score += 1;
  if (intentLower.includes("csrf") && owasp.includes("a01"))   score += 1;
  return score;
}

function formatThreat(t: CatalogThreat) {
  const amp = parseAmplification(t.aiAmplification);
  return {
    publicId:            t.publicId,
    cveId:               t.cveId,
    name:                t.name,
    severity:            t.severity,
    isActivelyExploited: t.isActivelyExploited,
    ruleContext:         amp?.ruleContext ?? null,
    patternLines:        amp?.patternLines ?? [],
  };
}

// ── IDE formatting ─────────────────────────────────────────────────────────────

const LAYER_ORDER = [
  "auth_session", "authz_access", "input_validation", "secrets_credentials",
  "dependency_supply", "data_privacy", "api_security", "database",
  "infrastructure", "caching_cdn", "frontend_network", "observability",
  "resilience", "ai_safety", "code_quality",
];

interface IdeFormat {
  filename: (stack: string) => string;
  prefix: (stack: string) => string;
  usageTip: string;
}

const IDE_FORMATS: Record<string, IdeFormat> = {
  cursor: {
    filename: (stack) => `.cursor/rules/aigently-${stack}-security.mdc`,
    prefix: (stack) => `---\ndescription: Aigent.ly security guardrails for ${stack}\nalwaysApply: true\n---\n\n`,
    usageTip: "Save to .cursor/rules/ directory. Cursor auto-loads *.mdc files.",
  },
  "claude-code": {
    filename: () => "CLAUDE.md",
    prefix: (stack) => `# CLAUDE.md — ${stack} security guardrails (aigent.ly)\n\n`,
    usageTip: "Save as CLAUDE.md in your project root. Claude Code loads it automatically.",
  },
  windsurf: {
    filename: () => ".windsurfrules",
    prefix: (stack) => `# Aigent.ly security guardrails — ${stack}\n\n`,
    usageTip: "Save as .windsurfrules in your project root.",
  },
  copilot: {
    filename: () => ".github/copilot-instructions.md",
    prefix: (stack) => `# GitHub Copilot Instructions — ${stack} security (aigent.ly)\n\n`,
    usageTip: "Save to .github/copilot-instructions.md in your repo root.",
  },
  cline: {
    filename: () => ".clinerules",
    prefix: (stack) => `# Aigent.ly security guardrails — ${stack}\n\n`,
    usageTip: "Save as .clinerules in your project root.",
  },
};

function getIdeFormat(ideSlug: string): IdeFormat {
  return IDE_FORMATS[ideSlug] ?? {
    filename: (stack) => `aigently-${stack}-security.md`,
    prefix: (stack) => `# Aigent.ly security guardrails — ${stack}\n\n`,
    usageTip: `Save as the appropriate rules file for your IDE.`,
  };
}

// ── Tool: get_security_context ─────────────────────────────────────────────────

interface GetSecurityContextInput {
  intent: string;
  file_path?: string;
  stacks?: string[];
  ide?: string; // injected from DEFAULT_IDE by the server; users never set this manually
}

export function handleGetSecurityContext(input: GetSecurityContextInput) {
  const { intent, file_path, stacks: explicitStacks, ide = "claude-code" } = input;
  const { stacks: detectedStacks, ruleType } = detectContext(intent, file_path, explicitStacks);
  const intentLower = intent.toLowerCase();

  const allRules   = getRules();
  const allThreats = getThreats();

  const matchedRules: CatalogRule[] = [];
  for (const r of allRules) {
    if (!r.stacks.some(s => detectedStacks.includes(s))) continue;
    // IDE filter: skip rules that are explicitly restricted to other IDEs
    if (r.ides && r.ides.length > 0 && !r.ides.includes(ide)) continue;
    // Prefer the structured ruleType field; fall back to slug-pattern for older exports
    const rType = r.ruleType ?? (
      r.slug.endsWith("-security-patterns-v1") ? "pattern" :
      r.slug.endsWith("-security-deps-v1")     ? "deps"    : null
    );
    if (ruleType === "patterns" && rType === "pattern") matchedRules.push(r);
    else if (ruleType === "deps" && rType === "deps")   matchedRules.push(r);
    else if (ruleType === "both")                       matchedRules.push(r);
  }

  const linkedThreatIds = new Set(matchedRules.flatMap(r => r.threatIds));
  const stackThreats = allThreats.filter(t =>
    t.stacks.some(s => detectedStacks.includes(s))
  );

  const scored = stackThreats
    .map(t => ({ t, score: scoreThreat(t, linkedThreatIds, intentLower) }))
    .sort((a, b) => b.score - a.score || sevScore(a.t.severity) - sevScore(b.t.severity));

  const topThreats = scored.slice(0, 5).map(({ t }) => formatThreat(t));

  const exploitedCount = topThreats.filter(t => t.isActivelyExploited).length;
  const stackLabel = detectedStacks.join(", ") || "unknown stack";
  const injection_hint = detectedStacks.length
    ? `Injecting ${stackLabel} security ${ruleType} rule` +
      (exploitedCount > 0 ? ` (${exploitedCount} actively exploited CVE${exploitedCount > 1 ? "s" : ""})` : "")
    : "No matching stack detected — returning general threat data";

  return {
    detected_stacks: detectedStacks,
    rules: matchedRules.map(r => {
      const rType = r.ruleType ?? (
        r.slug.endsWith("-security-patterns-v1") ? "pattern" :
        r.slug.endsWith("-security-deps-v1")     ? "deps"    : "unknown"
      );
      return {
        slug:       r.slug,
        name:       r.name,
        type:       rType,
        bodyMdx:    r.bodyMdx,
        summaryMdx: r.summaryMdx,
      };
    }),
    top_threats:     topThreats,
    injection_hint,
  };
}

// ── Tool: compose_guardrail ────────────────────────────────────────────────────

interface ComposeGuardrailInput {
  stack_slug: string;
  intent?: string;
  layer_slugs?: string[];
  target_ide?: string;
  rule_type?: string; // "all" | "pattern" | "deps" — filters rule fallback content
}

export function handleComposeGuardrail(input: ComposeGuardrailInput) {
  const { stack_slug, intent, layer_slugs, target_ide = "claude-code", rule_type = "all" } = input;

  // 1. Resolve which layers to include
  const resolvedLayers: string[] = layer_slugs && layer_slugs.length > 0
    ? layer_slugs
    : intent
    ? resolveLayersFromIntent(intent)
    : LAYER_ORDER; // all layers if no intent

  // Sort by canonical layer order for consistent output
  const orderedLayers = [...resolvedLayers].sort(
    (a, b) => LAYER_ORDER.indexOf(a) - LAYER_ORDER.indexOf(b)
  );

  // 2. Look up pre-synthesized guardrail blocks from guardrails.json
  const allGuardrails = getGuardrails();
  const guardrailMap = new Map(
    allGuardrails.map(g => [`${g.stackSlug}::${g.layerSlug}`, g.content])
  );

  const blocks: string[] = [];
  const layersUsed: string[] = [];
  const layersMissingGuardrail: string[] = [];

  for (const layerSlug of orderedLayers) {
    const content = guardrailMap.get(`${stack_slug}::${layerSlug}`);
    if (content) {
      blocks.push(content.trim());
      layersUsed.push(layerSlug);
    } else {
      layersMissingGuardrail.push(layerSlug);
    }
  }

  // 3. Fallback: for layers with no guardrail, assemble from rules.json bodyMdx
  //    Apply rule_type + IDE filter
  if (layersMissingGuardrail.length > 0) {
    const allRules = getRules();
    for (const layerSlug of layersMissingGuardrail) {
      const matchingRules = allRules.filter(r => {
        if (!r.stacks.includes(stack_slug)) return false;
        // Rules with no layer assignment are treated as "unassigned" — only
        // surface them under dependency_supply (their conventional home), not
        // every layer. Without this guard, a deps rule with layers:[] floods
        // every fallback block (the 221KB repeat bug).
        if (r.layers.length === 0 && layerSlug !== "dependency_supply") return false;
        if (r.layers.length > 0 && !r.layers.includes(layerSlug)) return false;
        // IDE filter: skip rules restricted to other IDEs
        if (r.ides && r.ides.length > 0 && !r.ides.includes(target_ide)) return false;
        if (rule_type === "all") return true;
        const rType = r.ruleType ?? (
          r.slug.endsWith("-security-patterns-v1") ? "pattern" :
          r.slug.endsWith("-security-deps-v1")     ? "deps"    : null
        );
        return rType === rule_type;
      });
      if (matchingRules.length > 0) {
        const combined = matchingRules
          .map(r => (r.bodyMdx ?? "").trim())
          .filter(Boolean)
          .join("\n\n---\n\n");
        if (combined) {
          blocks.push(combined);
          layersUsed.push(layerSlug);
        }
      }
    }
  }

  if (blocks.length === 0) {
    return {
      error: "no_content_found",
      stack: stack_slug,
      layers_requested: resolvedLayers,
      message: `No guardrail content found for stack "${stack_slug}" on the requested layers. Use list_stacks to see available stacks.`,
      fallback_tip: "Use get_security_context with your intent to retrieve rules by stack detection.",
    };
  }

  // 4. Apply IDE-specific formatting
  const ide = getIdeFormat(target_ide);
  const stackName = getStacks().find(s => s.slug === stack_slug)?.name ?? stack_slug;
  const body = blocks.join("\n\n---\n\n");
  const guardrail = ide.prefix(stackName) + body;
  const filename = ide.filename(stack_slug);

  return {
    guardrail,
    filename,
    meta: {
      stack: stack_slug,
      layers_used: layersUsed,
      guardrail_count: blocks.length,
      target_ide,
      generated_from: "static_catalog",
    },
    usage_tip: ide.usageTip,
  };
}

// ── Tool: list_stacks ──────────────────────────────────────────────────────────

export function handleListStacks() {
  return getStacks().map(s => ({
    slug:          s.slug,
    name:          s.name,
    catalogStatus: s.catalogStatus,
    ecosystem:     s.ecosystem,
    securityGrade: s.securityGrade,
  }));
}

// ── Tool: get_rule ─────────────────────────────────────────────────────────────

interface GetRuleInput { slug: string }

export function handleGetRule(input: GetRuleInput) {
  const r = getRules().find(r => r.slug === input.slug);
  if (!r) return { error: `Rule not found: ${input.slug}` };
  return {
    slug:          r.slug,
    name:          r.name,
    description:   r.description,
    version:       r.version,
    bodyMdx:       r.bodyMdx,
    summaryMdx:    r.summaryMdx,
    stacks:        r.stacks,
    layers:        r.layers,
    linkedThreats: r.threatIds.length,
  };
}

// ── Tool: search_threats ───────────────────────────────────────────────────────

interface SearchThreatsInput {
  query?:      string;
  severity?:   string;
  owasp_ref?:  string;
  stack_slug?: string;
  layer_slug?: string; // filter by protection layer slug (e.g. "auth_session")
  limit?:      number;
}

export function handleSearchThreats(input: SearchThreatsInput) {
  const { query, severity, owasp_ref, stack_slug, layer_slug, limit = 20 } = input;
  const q = query?.toLowerCase();

  const results = getThreats().filter(t => {
    if (severity   && t.severity !== severity)                                                    return false;
    if (owasp_ref  && !t.owaspRefs.some(r => r.toUpperCase().includes(owasp_ref.toUpperCase()))) return false;
    if (stack_slug && !t.stacks.includes(stack_slug))                                             return false;
    if (layer_slug && !(t.layers ?? []).includes(layer_slug))                                     return false;
    if (q && !t.name.toLowerCase().includes(q) && !t.description?.toLowerCase().includes(q))     return false;
    return true;
  });

  return results
    .sort((a, b) => sevScore(a.severity) - sevScore(b.severity))
    .slice(0, limit)
    .map(t => ({
      publicId:            t.publicId,
      cveId:               t.cveId,
      name:                t.name,
      severity:            t.severity,
      isActivelyExploited: t.isActivelyExploited,
      owaspRefs:           t.owaspRefs,
      stacks:              t.stacks,
      layers:              t.layers ?? [],
    }));
}

// ── Tool: get_threat ───────────────────────────────────────────────────────────

interface GetThreatInput { id: string }

export function handleGetThreat(input: GetThreatInput) {
  const { id } = input;
  const t = getThreats().find(t => t.publicId === id || t.cveId === id);
  if (!t) return { error: `Threat not found: ${id}` };

  const amp = parseAmplification(t.aiAmplification);
  return {
    publicId:            t.publicId,
    cveId:               t.cveId,
    source:              t.source,
    sourceUrl:           t.sourceUrl,
    family:              t.family,
    name:                t.name,
    description:         t.description,
    severity:            t.severity,
    owaspRefs:           t.owaspRefs,
    isActivelyExploited: t.isActivelyExploited,
    affectedProducts:    t.affectedProducts,
    stacks:              t.stacks,
    aiAmplification:     amp,
    publishedAt:         t.publishedAt,
  };
}

// ── Tool: get_manifest ─────────────────────────────────────────────────────────

export function handleGetManifest() {
  return getManifest();
}

// ── Tool: detect_project_stack ─────────────────────────────────────────────────

interface DetectProjectStackInput {
  file_paths: string[];
  intent?: string;
}

// Core layers to suggest when no intent is provided
const CORE_LAYERS = ["auth_session", "input_validation", "secrets_credentials", "api_security"];

export function handleDetectProjectStack(input: DetectProjectStackInput) {
  const { file_paths, intent = "" } = input;
  // Join all file paths into a single string for file-path signal matching
  const fileHaystack = file_paths.join(" ").toLowerCase();

  const { stacks: detectedStacks } = detectContext(intent, fileHaystack);
  const suggestedLayers = intent
    ? resolveLayersFromIntent(intent)
    : CORE_LAYERS;

  const allGuardrails = getGuardrails();
  const allStacks     = getStacks();

  if (detectedStacks.length === 0) {
    return {
      detected_stacks: [],
      message: "Could not detect a stack from the provided file paths. Try passing more files (e.g. package.json, go.mod, requirements.txt, next.config.ts) or call list_stacks to find the right slug manually.",
      suggested_next: "list_stacks",
    };
  }

  const primaryStack = detectedStacks[0];
  const stackMeta    = allStacks.find(s => s.slug === primaryStack);

  // Find which layers have pre-synthesized guardrails for the detected stack
  const availableLayers = [...new Set(
    allGuardrails.filter(g => g.stackSlug === primaryStack).map(g => g.layerSlug)
  )];
  const layersToUse = availableLayers.length > 0
    ? suggestedLayers.filter(l => availableLayers.includes(l)).concat(
        suggestedLayers.filter(l => !availableLayers.includes(l))
      )
    : suggestedLayers;

  return {
    detected_stacks: detectedStacks,
    primary_stack:   primaryStack,
    stack_name:      stackMeta?.name ?? primaryStack,
    catalog_status:  stackMeta?.catalogStatus ?? "unknown",
    suggested_layers: layersToUse,
    guardrail_layers_available: availableLayers,
    compose_call: {
      tool: "compose_guardrail",
      arguments: {
        stack_slug:  primaryStack,
        layer_slugs: layersToUse,
      },
      tip: "Call compose_guardrail with these arguments to get your security guardrail file.",
    },
  };
}
