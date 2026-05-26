# Aigently MCP Server — Cursor Integration Guide

This guide shows you how to wire up the Aigently security guardrails MCP server
to Cursor so that every time you ask Cursor to write code, it automatically has
the relevant CVE threats and security rules in context.

No API key. No sign-up. No network calls. The server reads local JSON files.

---

## How it works in 30 seconds

```
You type: "Add a login endpoint with JWT"
    ↓
Cursor calls: get_security_context("Add a login endpoint with JWT", "app/api/auth.ts")
    ↓
MCP server returns: matching rules + top 5 CVEs for your stack
    ↓
Cursor injects all of that into the prompt before generating code
    ↓
Result: Cursor writes code that doesn't have auth bypass bugs
```

The MCP server is a local Node.js process. It reads from
`packages/catalog-data/*.json` which are updated daily from the Aigently
pipeline and committed to this repo.

---

## Part 1 — Install

### 1.1 Clone the repo

```bash
git clone https://github.com/aigently/aigently-catalog.git
cd aigently-catalog
```

### 1.2 Install dependencies

```bash
npm install
```

### 1.3 Verify the server works

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | node packages/mcp-server/dist/index.js
```

You should see a JSON list of 8 tools. If you get an error, check that
`packages/catalog-data/stacks.json` exists. See the
[troubleshooting section](#troubleshooting) if it does not.

---

## Part 2 — Connect to Cursor

Cursor supports MCP servers via a JSON config file. You can configure this
per-project (affects only one repo) or globally (affects all your projects).

### Option A — Per-project (recommended)

Create `.cursor/mcp.json` in the root of the project you are working on:

```bash
mkdir -p /path/to/your-project/.cursor
touch /path/to/your-project/.cursor/mcp.json
```

Paste this content, replacing the path with the actual location of this repo:

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/aigently-catalog/packages/mcp-server/dist/index.js"]
    }
  }
}
```

To get the absolute path, run this inside the `aigently-catalog` directory:

```bash
echo "$(pwd)/packages/mcp-server/dist/index.js"
```

Copy that output and paste it as the arg above.

### Option B — Global (all projects)

Create or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/ABSOLUTE/PATH/TO/aigently-catalog/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### 2.1 Restart Cursor

After saving the config file, restart Cursor completely (quit and reopen — not
just reload the window). This is required for the MCP server to be picked up.

### 2.2 Verify Cursor can see the tools

1. Open the Cursor Command Palette (`Cmd+Shift+P` or `Ctrl+Shift+P`).
2. Type `MCP` and look for **"MCP: List Tools"** or **"Model Context Protocol"**.
3. You should see `aigently` listed with 8 tools.

Alternatively, open a chat and type:

```
List available aigently security tools
```

Cursor will call `list_stacks` and show you the supported tech stacks.

---

## Part 3 — Using the tools

The MCP tools run automatically when Cursor detects relevant intent. You can
also call them explicitly.

### Automatic usage — just write code normally

When you are working in a file and ask Cursor to implement something
security-sensitive, it will automatically call `get_security_context`:

```
# In a Next.js project, working in app/api/auth/route.ts

"Add a login endpoint that validates credentials and returns a JWT"
```

Cursor will call `get_security_context` with your intent and file path,
get back the relevant CVEs and security rules, and inject them into the
code generation context before writing a single line.

### Explicit — compose a guardrail file for your project

Ask Cursor to generate the right guardrail file for your stack and IDE:

```
Use the aigently compose_guardrail tool to generate security rules
for my Next.js project, targeting Cursor format
```

Cursor will return a complete `.mdc` file with the correct frontmatter.
Save it to `.cursor/rules/` and Cursor will load it automatically on
every chat in that project.

### Explicit — search for a specific CVE

```
Search aigently threats for "prototype pollution" affecting express
```

### Explicit — get full CVE details

```
Get aigently threat details for CVE-2025-29927
```

---

## Part 4 — Setting up permanent security rules

The most powerful way to use this is to generate a guardrail file and
commit it to your project so every developer on the team gets the rules.

### Step 1 — Generate the guardrail

In a Cursor chat:

```
Use aigently compose_guardrail with:
  stack_slug: "nextjs"
  target_ide: "cursor"
  layer_slugs: ["auth_session", "input_validation", "secrets_credentials", "api_security"]
```

Cursor will return something like:

```
filename: .cursor/rules/aigently-nextjs-security.mdc
guardrail: ---
description: Aigent.ly security guardrails for Next.js
alwaysApply: true
---

## Authentication & Session Security — Next.js Guardrails

ALWAYS perform authorization checks inside every Next.js route handler...
[hundreds of lines of rules]
```

### Step 2 — Save the file

```bash
mkdir -p .cursor/rules
# Paste the guardrail content into:
vim .cursor/rules/aigently-nextjs-security.mdc
```

### Step 3 — Commit it

```bash
git add .cursor/rules/aigently-nextjs-security.mdc
git commit -m "feat: add aigently security guardrails for Next.js"
```

Every developer who clones the repo and uses Cursor will now have these
security rules enforced automatically.

### Step 4 — Update when the catalog refreshes

The Aigently pipeline runs daily. When you want fresher rules:

```bash
cd aigently-catalog
git pull
```

Then re-run the compose step above to get updated guardrail content.

---

## Available stacks

Run this to see the current list:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_stacks","arguments":{}}}' \
  | node packages/mcp-server/dist/index.js \
  | python3 -c "import json,sys; [print(s['slug'], '-', s['name']) for s in json.loads(json.load(sys.stdin)['result']['content'][0]['text'])]"
```

Current stacks: `nextjs`, `express`, `fastapi`, `nestjs`, `nuxt`,
`react-spa`, `django`, `rails`, `go`, `ios`, `android`.

---

## Available protection layers

The 15 security layers you can pass to `compose_guardrail` via `layer_slugs`:

| Slug | Concern |
|------|---------|
| `auth_session` | Authentication bypass, session fixation, credential exposure |
| `authz_access` | Ownership checks, RLS, privilege escalation |
| `input_validation` | Injection attacks, path traversal, malformed input |
| `secrets_credentials` | Credential leakage, hardcoded secrets |
| `dependency_supply` | Package pinning, audit hygiene, supply chain |
| `data_privacy` | PII handling, encryption at rest, GDPR |
| `api_security` | Rate limiting, CORS, versioning, endpoint auth |
| `database` | RLS, connection pooling, column encryption |
| `infrastructure` | CI/CD secret hygiene, IAM, env isolation |
| `caching_cdn` | Cache poisoning, stale auth data, CDN header bypass |
| `frontend_network` | CSP, HTTPS-only cookies, SRI, clickjacking |
| `observability` | Log hygiene, alerting, audit trails |
| `resilience` | Backup strategy, failover, runbook coverage |
| `ai_safety` | Prompt injection, LLM output validation, context leakage |
| `code_quality` | Error handling, null safety, vulnerability-entry patterns |

---

## Troubleshooting

### Cursor says "MCP server failed to start" or "aigently not available"

1. Confirm the path in `mcp.json` is absolute (not relative):
   ```bash
   ls /ABSOLUTE/PATH/TO/aigently-catalog/packages/mcp-server/dist/index.js
   ```
   The file must exist and be readable.

2. Confirm Node.js is accessible:
   ```bash
   /usr/local/bin/node --version   # or wherever your node lives
   which node
   ```
   If `which node` shows a path under `~/.nvm` or similar, Cursor's sandboxed
   environment may not see it. Use the absolute Node.js path in `mcp.json`:
   ```json
   {
     "mcpServers": {
       "aigently": {
         "command": "/Users/you/.nvm/versions/node/v20.0.0/bin/node",
         "args": ["/absolute/path/to/dist/index.js"]
       }
     }
   }
   ```

3. Rebuild the server after any source changes:
   ```bash
   cd aigently-catalog
   npm run build -w @aigently/mcp-server
   ```

4. Restart Cursor completely after changing `mcp.json`.

### Tools run but return no rules or empty guardrails

The catalog data may be sparse for your stack. Check:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_manifest","arguments":{}}}' \
  | node packages/mcp-server/dist/index.js | python3 -m json.tool
```

Look at `counts.guardrails`. If it is low (e.g., 6), only a few stack×layer
combinations have pre-synthesized guardrail blocks. The server will fall back
to rule `bodyMdx` content for uncovered layers.

To get more coverage, run the Aigently pipeline's `summarize:layers` phase.

### I want to test a specific tool without Cursor

Every tool supports direct JSON-RPC calls:

```bash
node packages/mcp-server/dist/index.js <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name": "compose_guardrail",
  "arguments": {
    "stack_slug": "express",
    "target_ide": "cursor",
    "layer_slugs": ["auth_session", "input_validation"]
  }
}}
EOF
```

---

## Reference — mcp.json for other IDEs

### Claude Code (`~/.claude/settings.json`)

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/absolute/path/to/aigently-catalog/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Windsurf (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/absolute/path/to/aigently-catalog/packages/mcp-server/dist/index.js"]
    }
  }
}
```

### Cline (VS Code extension settings)

In VS Code settings (`Cmd+Shift+P → "Open User Settings JSON"`):

```json
{
  "cline.mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/absolute/path/to/aigently-catalog/packages/mcp-server/dist/index.js"]
    }
  }
}
```
