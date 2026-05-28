# @aigently/mcp-server

> Inject real CVE threat data and security guardrails into any AI coding assistant.

Connects Cursor, Claude Code, Windsurf, GitHub Copilot, and Cline to the
[Aigent.ly](https://aigent.ly) security catalog — 100+ CVEs updated daily from
NVD, GHSA, CISA KEV, OSV, and npm Audit. Free, no API key required.

**Zero configuration. No API key. No database. No network calls at runtime.**
The server reads static JSON files committed to this repo and updated daily.

---

## Install

### Option A — npx (no clone needed, always latest)

Use this directly in your IDE config — no installation step required:

```json
{
  "mcpServers": {
    "aigently": {
      "command": "npx",
      "args": ["-y", "@aigently/mcp-server"],
      "env": { "AIGENTLY_TARGET_IDE": "cursor" }
    }
  }
}
```

Change `AIGENTLY_TARGET_IDE` to `cursor`, `claude-code`, `windsurf`, `copilot`, or `cline`.

### Option B — Clone (for local development or offline use)

#### Step 1 — Get the server path

```bash
git clone https://github.com/aelbuni/aigently-catalog.git
cd aigently-catalog
npm install
npm run build -w @aigently/mcp-server
echo "$(pwd)/packages/mcp-server/dist/index.js"
```

Copy the path printed by that last command. You will paste it in the next step.

#### Step 2 — Add to your IDE

Pick your IDE below. Replace `/PASTE/PATH/HERE` with the path you copied.

---

#### Cursor

Create or edit `.cursor/mcp.json` in your project root (or `~/.cursor/mcp.json` for all projects):

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/PASTE/PATH/HERE"],
      "env": { "AIGENTLY_TARGET_IDE": "cursor" }
    }
  }
}
```

Restart Cursor. The server starts automatically.

---

#### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/PASTE/PATH/HERE"],
      "env": { "AIGENTLY_TARGET_IDE": "claude-code" }
    }
  }
}
```

---

#### Windsurf

Create or edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/PASTE/PATH/HERE"],
      "env": { "AIGENTLY_TARGET_IDE": "windsurf" }
    }
  }
}
```

---

#### GitHub Copilot (VS Code)

Open VS Code settings (`Cmd+Shift+P → "Open User Settings JSON"`):

```json
{
  "github.copilot.chat.mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/PASTE/PATH/HERE"],
      "env": { "AIGENTLY_TARGET_IDE": "copilot" }
    }
  }
}
```

---

#### Cline (VS Code extension)

```json
{
  "cline.mcpServers": {
    "aigently": {
      "command": "node",
      "args": ["/PASTE/PATH/HERE"],
      "env": { "AIGENTLY_TARGET_IDE": "cline" }
    }
  }
}
```

---

## How it works

When you ask your AI assistant to write security-sensitive code, it calls
`get_security_context` with your intent and the current file path. The server
detects your tech stack from the file path automatically — no configuration
needed — then returns the relevant security rules and top CVEs to enforce.

When you want to set up guardrails for a project from scratch, it calls
`detect_project_stack` with your project's root files, gets back the detected
stack, and calls `compose_guardrail` to generate a complete guardrail file in
the right format for your IDE.

```
Developer asks: "Add a login endpoint with JWT"
  ↓
IDE calls: get_security_context("Add a login endpoint with JWT", "app/api/auth/route.ts")
  ↓
Server detects: stack=nextjs (from file path), intent=auth (from text)
  ↓
Server returns: matching security rules + top 5 CVEs (e.g. CVE-2025-29927 auth bypass)
  ↓
IDE injects everything into the prompt before generating code
  ↓
Result: code that doesn't have auth bypass vulnerabilities
```

The `AIGENTLY_TARGET_IDE` env var tells the server which IDE is calling so it can
return IDE-specific rule content and format output files correctly. Set it once
in `mcp.json` and forget about it.

---

## Tools

| Tool | What it does |
|------|-------------|
| `detect_project_stack` | Detect tech stack from root file list — call this first when setting up a new project |
| `get_security_context` | Get security rules + CVEs for a coding task (auto-detects stack from file path) |
| `compose_guardrail` | Generate a complete IDE-ready guardrail file for a stack (`rule_type`: `all` \| `patterns` \| `deps`) |
| `list_stacks` | List all 11 supported stacks with slugs |
| `list_layers` | List protection layer taxonomy (informational — use `rule_type` in compose_guardrail instead) |
| `search_threats` | Search the CVE catalog by keyword, severity, OWASP category, or layer |
| `get_threat` | Full CVE details + AI-generated guardrail patterns |
| `get_rule` | Full security rule body + AI summary |
| `get_manifest` | Catalog version, last updated, and counts |

### Generated file locations by IDE

| `AIGENTLY_TARGET_IDE` | Output file |
|-----------------------|-------------|
| `cursor` | `.cursor/rules/aigently-{stack}-security.mdc` |
| `claude-code` | `CLAUDE.md` |
| `windsurf` | `.windsurfrules` |
| `copilot` | `.github/copilot-instructions.md` |
| `cline` | `.clinerules` |

---

## Catalog contents

The JSON files in `packages/catalog-data/` are generated by the Aigently pipeline
and committed here. Updated daily.

| File | Contents |
|------|---------|
| `threats.json` | CVEs with severity, OWASP refs, affected stacks, AI guardrail patterns — updated daily |
| `rules.json` | Security rules with full `bodyMdx`, layer and IDE assignments |
| `guardrails.json` | Pre-synthesized guardrail blocks per (stack, rule_type) — patterns and deps |
| `stacks.json` | 11 supported tech stacks |
| `manifest.json` | Generation timestamp and counts |

**Supported stacks:** Next.js, Express, FastAPI, NestJS, Nuxt, React SPA, Django, Rails, Go, iOS, Android

**Protection layers:** auth_session, authz_access, input_validation, secrets_credentials,
dependency_supply, data_privacy, api_security, database, infrastructure, caching_cdn,
frontend_network, observability, resilience, ai_safety, code_quality

---

## Keeping the catalog fresh

The catalog updates automatically via the daily Aigently pipeline. To update manually:

```bash
cd aigently-catalog
git pull
```

No rebuild needed — the server reads the JSON files at runtime.

---

## Verify it works

```bash
# List all tools
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | node packages/mcp-server/dist/index.js | python3 -m json.tool

# Test stack detection
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
  "name": "detect_project_stack",
  "arguments": {"file_paths": ["package.json","next.config.ts","app/","tsconfig.json"]}
}}' | node packages/mcp-server/dist/index.js | python3 -m json.tool

# Run the full smoke test suite
node packages/mcp-server/scripts/test-tools.mjs
```

---

## Contributing

The catalog data comes from the [Aigent.ly](https://aigent.ly) pipeline. To
contribute new stacks or protection rules, open an issue or PR in this repo.

To contribute to the MCP server code, see [DEVELOPMENT.md](../../DEVELOPMENT.md).

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
