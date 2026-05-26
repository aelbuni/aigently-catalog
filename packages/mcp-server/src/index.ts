#!/usr/bin/env node
import { createRequire } from "module";
import { Server }               from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const { version: PKG_VERSION } = createRequire(import.meta.url)("../package.json") as { version: string };

import {
  handleGetSecurityContext,
  handleComposeGuardrail,
  handleListStacks,
  handleGetRule,
  handleSearchThreats,
  handleGetThreat,
  handleGetManifest,
  handleDetectProjectStack,
} from "./tools.js";

// IDE identity — set once in mcp.json env, never passed per-call by the LLM.
// Valid values: cursor | claude-code | windsurf | copilot | cline
export const DEFAULT_IDE = (process.env.AIGENTLY_TARGET_IDE ?? "claude-code").toLowerCase();

const LAYER_TAXONOMY = [
  { slug: "auth_session",        name: "Authentication & Session",          tier: "core",           concern: "preventing authentication bypass, session fixation, and credential exposure" },
  { slug: "authz_access",        name: "Authorization & Access Control",    tier: "core",           concern: "enforcing ownership checks, RLS, and privilege boundaries" },
  { slug: "input_validation",    name: "Input Validation & Sanitization",   tier: "core",           concern: "preventing injection attacks, path traversal, and malformed input" },
  { slug: "secrets_credentials", name: "Secrets & Credentials",             tier: "core",           concern: "preventing credential leakage and hardcoded secrets" },
  { slug: "dependency_supply",   name: "Dependency & Supply Chain",         tier: "core",           concern: "package pinning, audit hygiene, and transitive dep safety" },
  { slug: "data_privacy",        name: "Data Privacy & Compliance",         tier: "core",           concern: "PII handling, encryption at rest, and GDPR-pattern compliance" },
  { slug: "api_security",        name: "API Security & Rate Limiting",      tier: "infrastructure", concern: "throttling, CORS, versioning, and endpoint authentication" },
  { slug: "database",            name: "Database Hardening",                tier: "infrastructure", concern: "RLS, connection pooling, backup hygiene, and column encryption" },
  { slug: "infrastructure",      name: "Infrastructure & Deployment",       tier: "infrastructure", concern: "CI/CD secret hygiene, IAM least-privilege, and env isolation" },
  { slug: "caching_cdn",         name: "Caching & CDN",                     tier: "infrastructure", concern: "cache poisoning, stale auth data, and CDN security header bypass" },
  { slug: "frontend_network",    name: "Frontend & Network Security",       tier: "infrastructure", concern: "CSP, HTTPS-only cookies, SRI, and clickjacking defenses" },
  { slug: "observability",       name: "Observability & Incident Response", tier: "operational",    concern: "log hygiene, alerting, audit trails, and error boundary patterns" },
  { slug: "resilience",          name: "Resilience & Recovery",             tier: "operational",    concern: "backup strategy, failover, AZ distribution, and runbook coverage" },
  { slug: "ai_safety",           name: "AI & LLM Safety",                   tier: "operational",    concern: "prompt injection defense, LLM output validation, and context leakage" },
  { slug: "code_quality",        name: "Code Quality & Patterns",           tier: "operational",    concern: "error handling, null safety, and patterns that prevent vulnerability entry" },
];

const server = new Server(
  { name: "@aigently/mcp-server", version: PKG_VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "detect_project_stack",
      description:
        "Detect the technology stack from project file paths and return a ready-to-use compose_guardrail call. " +
        "Call this FIRST when setting up security guardrails for a project — pass a list of files/directories " +
        "from the project root (e.g. package.json, next.config.ts, app/, go.mod). " +
        "Returns detected stack slugs, suggested protection layers, and the exact compose_guardrail arguments to run next.",
      inputSchema: {
        type: "object",
        properties: {
          file_paths: {
            type: "array",
            items: { type: "string" },
            description: "File and directory names from the project root, e.g. ['package.json', 'next.config.ts', 'app/', 'tsconfig.json', 'go.mod'].",
          },
          intent: {
            type: "string",
            description: "Optional: what the developer is building. Used to narrow the suggested protection layers.",
          },
        },
        required: ["file_paths"],
      },
    },
    {
      name: "get_security_context",
      description:
        "Inject real CVE threat data and security rules into the AI context for the current coding task. " +
        "Pass the current file path — the tech stack is auto-detected from it (e.g. 'app/api/auth/route.ts' → nextjs). " +
        "Also pass what the developer is building as intent text. " +
        "Returns matching security rules (bodyMdx) and the top 5 relevant CVEs to enforce while generating code. " +
        "Use this whenever the developer is implementing anything security-sensitive: auth, APIs, data handling, deps.",
      inputSchema: {
        type: "object",
        properties: {
          intent: {
            type: "string",
            description: "What the developer is building or implementing (free text). E.g. 'add JWT login endpoint'.",
          },
          file_path: {
            type: "string",
            description: "The current file path being edited. Used to auto-detect the tech stack. E.g. 'app/api/auth/route.ts'.",
          },
          stacks: {
            type: "array",
            items: { type: "string" },
            description: "Explicit stack slugs if already known (e.g. ['nextjs']). Skips auto-detection when provided.",
          },
          ide: {
            type: "string",
            description: "Override the IDE for rule filtering. Usually not needed — set AIGENTLY_TARGET_IDE env var in mcp.json instead.",
          },
        },
        required: ["intent"],
      },
    },
    {
      name: "compose_guardrail",
      description:
        "Generate a complete, IDE-ready security guardrail file for a tech stack. " +
        "Returns the full guardrail content with the correct filename for the configured IDE " +
        "(cursor → .cursor/rules/*.mdc, claude-code → CLAUDE.md, windsurf → .windsurfrules, etc.). " +
        "Save the returned file to your project root and your AI assistant will enforce the rules automatically. " +
        "If you don't know the stack_slug, call detect_project_stack first.",
      inputSchema: {
        type: "object",
        properties: {
          stack_slug: {
            type: "string",
            description: "Technology stack slug, e.g. 'nextjs', 'express', 'fastapi'. Use list_stacks to see all options.",
          },
          intent: {
            type: "string",
            description:
              "What you are building — used to select the most relevant protection layers automatically. " +
              "E.g. 'user auth with JWT and Supabase RLS', 'public REST API with rate limiting'.",
          },
          layer_slugs: {
            type: "array",
            items: { type: "string" },
            description:
              "Explicit protection layer slugs to include. Inferred from intent when omitted. " +
              "Options: auth_session, authz_access, input_validation, secrets_credentials, " +
              "dependency_supply, data_privacy, api_security, database, infrastructure, " +
              "caching_cdn, frontend_network, observability, resilience, ai_safety, code_quality.",
          },
          target_ide: {
            type: "string",
            description:
              "IDE format override: cursor | claude-code | windsurf | copilot | cline. " +
              "Defaults to the AIGENTLY_TARGET_IDE env var set in mcp.json — you usually don't need to pass this.",
          },
          rule_type: {
            type: "string",
            description: "Filter rules by type: all | pattern | deps. Defaults to all.",
          },
        },
        required: ["stack_slug"],
      },
    },
    {
      name: "list_stacks",
      description: "List all supported technology stacks with slug, name, ecosystem, and catalog status. Use slugs with compose_guardrail and search_threats.",
      inputSchema: { type: "object", properties: {}, required: [] },
    },
    {
      name: "get_rule",
      description: "Get the full security rule content (bodyMdx + AI summary + layer assignments) for a given rule slug.",
      inputSchema: {
        type: "object",
        properties: {
          slug: { type: "string", description: "Rule slug, e.g. 'nextjs-security-patterns-v1'. Use list_stacks to discover rule slugs." },
        },
        required: ["slug"],
      },
    },
    {
      name: "search_threats",
      description: "Search the CVE/advisory catalog with optional filters. Returns threats sorted by severity.",
      inputSchema: {
        type: "object",
        properties: {
          query:      { type: "string",  description: "Free-text search against threat name and description." },
          severity:   { type: "string",  description: "Filter by severity: critical | high | medium | low | info" },
          owasp_ref:  { type: "string",  description: "Filter by OWASP category, e.g. 'A02' or 'LLM01'." },
          stack_slug: { type: "string",  description: "Filter to threats affecting a specific stack (e.g. 'nextjs')." },
          layer_slug: { type: "string",  description: "Filter to threats assigned to a protection layer (e.g. 'auth_session')." },
          limit:      { type: "number",  description: "Max results to return (default 20)." },
        },
      },
    },
    {
      name: "get_threat",
      description: "Get full details for a single CVE including description, affected versions, and AI-generated guardrail patterns.",
      inputSchema: {
        type: "object",
        properties: {
          id: { type: "string", description: "CVE ID (e.g. 'CVE-2025-29927') or internal publicId." },
        },
        required: ["id"],
      },
    },
    {
      name: "list_layers",
      description: "List the 15 security protection layers used to organize guardrail rules (e.g. auth_session, input_validation, api_security).",
      inputSchema: { type: "object", properties: {}, required: [] },
    },
    {
      name: "get_manifest",
      description: "Get catalog metadata: version, last updated timestamp, and counts of threats, rules, stacks, and guardrails.",
      inputSchema: { type: "object", properties: {}, required: [] },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  // Inject DEFAULT_IDE into relevant tool inputs when no explicit ide/target_ide is provided
  const withIde = <T extends { ide?: string }>(input: T): T & { ide: string } =>
    ({ ...input, ide: input.ide ?? DEFAULT_IDE });

  const withTargetIde = <T extends { target_ide?: string }>(input: T): T & { target_ide: string } =>
    ({ ...input, target_ide: input.target_ide ?? DEFAULT_IDE });

  const result = await (async () => {
    switch (name) {
      case "detect_project_stack": return handleDetectProjectStack(args as unknown as Parameters<typeof handleDetectProjectStack>[0]);
      case "get_security_context": return handleGetSecurityContext(withIde(args as unknown as Parameters<typeof handleGetSecurityContext>[0]));
      case "compose_guardrail":    return handleComposeGuardrail(withTargetIde(args as unknown as Parameters<typeof handleComposeGuardrail>[0]));
      case "list_stacks":          return handleListStacks();
      case "get_rule":             return handleGetRule(args as unknown as Parameters<typeof handleGetRule>[0]);
      case "search_threats":       return handleSearchThreats(args as unknown as Parameters<typeof handleSearchThreats>[0]);
      case "get_threat":           return handleGetThreat(args as unknown as Parameters<typeof handleGetThreat>[0]);
      case "list_layers":          return { layers: LAYER_TAXONOMY, total: LAYER_TAXONOMY.length, tip: "Use layer slugs in compose_guardrail to get merged guardrails for specific concerns." };
      case "get_manifest":         return handleGetManifest();
      default:                     return { error: `Unknown tool: ${name}` };
    }
  })();

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
