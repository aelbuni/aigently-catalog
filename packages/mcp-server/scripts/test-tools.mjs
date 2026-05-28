#!/usr/bin/env node
/**
 * End-to-end smoke test for all MCP tools.
 * Runs against the built dist/index.js by sending JSON-RPC messages via stdio.
 * Exit 0 = all pass, Exit 1 = failures.
 *
 * Usage:
 *   node scripts/test-tools.mjs
 */
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.resolve(__dirname, "../dist/index.js");

const TESTS = [
  {
    name: "get_manifest",
    req: { method: "tools/call", params: { name: "get_manifest", arguments: {} } },
    validate: (r) => r.counts && typeof r.counts.threats === "number",
  },
  {
    name: "list_stacks",
    req: { method: "tools/call", params: { name: "list_stacks", arguments: {} } },
    validate: (r) => Array.isArray(r) && r.length > 0 && r[0].slug,
  },
  {
    name: "list_layers",
    req: { method: "tools/call", params: { name: "list_layers", arguments: {} } },
    validate: (r) => Array.isArray(r.layers) && r.layers.length === 15,
  },
  // ── Stack detection tests ────────────────────────────────────────────────────
  {
    name: "get_security_context — nextjs detected from keyword in intent",
    req: {
      method: "tools/call",
      params: {
        name: "get_security_context",
        arguments: {
          intent: "implementing JWT auth with refresh tokens in Next.js",
          file_path: "app/api/auth/route.ts",
        },
      },
    },
    validate: (r) => Array.isArray(r.detected_stacks) && r.detected_stacks.includes("nextjs"),
  },
  {
    name: "get_security_context — nextjs detected from file path alone (no keyword in intent)",
    req: {
      method: "tools/call",
      params: {
        name: "get_security_context",
        arguments: {
          intent: "add JWT auth",
          file_path: "app/api/auth/route.ts",
        },
      },
    },
    validate: (r) => r.detected_stacks.includes("nextjs"),
  },
  {
    name: "get_security_context — fastapi detected from pyproject.toml file path",
    req: {
      method: "tools/call",
      params: {
        name: "get_security_context",
        arguments: {
          intent: "add authentication",
          file_path: "pyproject.toml",
        },
      },
    },
    validate: (r) => r.detected_stacks.includes("fastapi"),
  },
  {
    name: "get_security_context — go detected from go.mod file path",
    req: {
      method: "tools/call",
      params: {
        name: "get_security_context",
        arguments: {
          intent: "add user authentication",
          file_path: "go.mod",
        },
      },
    },
    validate: (r) => r.detected_stacks.includes("go"),
  },
  {
    name: "get_security_context — graceful fallback for unknown stack (no file path)",
    req: {
      method: "tools/call",
      params: {
        name: "get_security_context",
        arguments: { intent: "add an API endpoint" },
      },
    },
    validate: (r) => typeof r.injection_hint === "string" && Array.isArray(r.top_threats),
  },
  // ── detect_project_stack ─────────────────────────────────────────────────────
  {
    name: "detect_project_stack — nextjs from file list",
    req: {
      method: "tools/call",
      params: {
        name: "detect_project_stack",
        arguments: {
          file_paths: ["package.json", "next.config.ts", "app/", "tsconfig.json"],
          intent: "user auth with JWT",
        },
      },
    },
    validate: (r) => r.detected_stacks.includes("nextjs") && r.compose_call?.arguments?.stack_slug === "nextjs",
  },
  {
    name: "detect_project_stack — fastapi from pyproject.toml",
    req: {
      method: "tools/call",
      params: {
        name: "detect_project_stack",
        arguments: { file_paths: ["pyproject.toml", "main.py", "routers/"] },
      },
    },
    validate: (r) => r.detected_stacks.includes("fastapi"),
  },
  {
    name: "detect_project_stack — unknown returns helpful message",
    req: {
      method: "tools/call",
      params: {
        name: "detect_project_stack",
        arguments: { file_paths: ["README.md", "data.csv"] },
      },
    },
    validate: (r) => Array.isArray(r.detected_stacks) && (r.detected_stacks.length === 0 || typeof r.message === "string" || r.compose_call !== undefined),
  },
  {
    name: "compose_guardrail (nextjs, cursor)",
    req: {
      method: "tools/call",
      params: {
        name: "compose_guardrail",
        arguments: { stack_slug: "nextjs", target_ide: "cursor", intent: "user auth" },
      },
    },
    validate: (r) => typeof r.guardrail === "string" && r.filename.endsWith(".mdc"),
  },
  {
    name: "compose_guardrail (fastapi, claude-code)",
    req: {
      method: "tools/call",
      params: {
        name: "compose_guardrail",
        arguments: { stack_slug: "fastapi", target_ide: "claude-code" },
      },
    },
    validate: (r) => typeof r.guardrail === "string" && r.filename === "CLAUDE.md",
  },
  {
    name: "get_rule (nextjs-security-patterns-v1)",
    req: {
      method: "tools/call",
      params: { name: "get_rule", arguments: { slug: "nextjs-security-patterns-v1" } },
    },
    validate: (r) => r.slug === "nextjs-security-patterns-v1" && r.bodyMdx,
  },
  {
    name: "search_threats (critical injections)",
    req: {
      method: "tools/call",
      params: {
        name: "search_threats",
        arguments: { query: "injection", severity: "critical", limit: 3 },
      },
    },
    validate: (r) => Array.isArray(r) && r.length > 0,
  },
  {
    name: "search_threats (layer_slug filter)",
    req: {
      method: "tools/call",
      params: {
        name: "search_threats",
        arguments: { layer_slug: "auth_session", limit: 5 },
      },
    },
    validate: (r) => Array.isArray(r),
  },
  {
    name: "get_threat (CVE-2025-29927)",
    req: {
      method: "tools/call",
      params: { name: "get_threat", arguments: { id: "CVE-2025-29927" } },
    },
    validate: (r) => r.cveId === "CVE-2025-29927" && r.aiAmplification?.patternLines?.length > 0,
  },
  {
    name: "get_threat (unknown — structured error)",
    req: {
      method: "tools/call",
      params: { name: "get_threat", arguments: { id: "CVE-9999-00000" } },
    },
    validate: (r) => typeof r.error === "string",
  },
];

function sendRequest(proc, req) {
  return new Promise((resolve, reject) => {
    const msg = JSON.stringify({ jsonrpc: "2.0", id: req.id ?? 1, ...req }) + "\n";
    let buf = "";

    const onData = (chunk) => {
      buf += chunk.toString();
      // Each response is a single JSON line
      const lines = buf.split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === (req.id ?? 1)) {
            proc.stdout.off("data", onData);
            resolve(parsed);
          }
        } catch { /* incomplete chunk, keep buffering */ }
      }
    };

    proc.stdout.on("data", onData);
    proc.stdin.write(msg);

    setTimeout(() => {
      proc.stdout.off("data", onData);
      reject(new Error("Timeout waiting for response"));
    }, 10_000);
  });
}

async function run() {
  const proc = spawn("node", [SERVER], { stdio: ["pipe", "pipe", "inherit"] });

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < TESTS.length; i++) {
    const test = TESTS[i];
    try {
      const response = await sendRequest(proc, { ...test.req, id: i + 1 });

      if (response.error) {
        console.error(`  ✗ ${test.name} — JSON-RPC error: ${JSON.stringify(response.error)}`);
        failed++;
        continue;
      }

      const content = response.result?.content?.[0]?.text;
      if (!content) {
        console.error(`  ✗ ${test.name} — no content in response`);
        failed++;
        continue;
      }

      const parsed = JSON.parse(content);
      if (test.validate(parsed)) {
        console.log(`  ✓ ${test.name}`);
        passed++;
      } else {
        console.error(`  ✗ ${test.name} — validation failed`);
        console.error("    response:", JSON.stringify(parsed).slice(0, 200));
        failed++;
      }
    } catch (err) {
      console.error(`  ✗ ${test.name} — ${err.message}`);
      failed++;
    }
  }

  proc.kill();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => { console.error(err); process.exit(1); });
