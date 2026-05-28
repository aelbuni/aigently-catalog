# Aigent.ly Catalog

**Free, open-source security guardrails for AI coding assistants.**

The open-source CVE catalog, pipeline, and MCP server that power [aigent.ly](https://aigent.ly). Every day, the pipeline pulls real CVEs from five public threat sources, enriches them with AI-generated coding patterns, and commits ready-to-use security rules directly into this repo — formatted for Cursor, Claude Code, Windsurf, GitHub Copilot, and Cline.

> "We open-sourced everything the community needs — the data, the pipeline, the stack registry.
> The web app that runs aigent.ly is private. Because a security product should practice what it preaches."

---

## Why this exists

AI coding assistants write production code fast. They don't know which CVEs affect your stack today, or how to write around them. Aigent.ly bridges that gap: it turns a live CVE feed into IDE rules that travel with your project, enforced at generation time — not discovered at audit time.

```text
CVE published  →  pipeline detects it  →  Claude generates safe-code patterns
    →  rule committed to this repo  →  your IDE enforces it while you type
```

---

## What's in this repo

| Path | What it contains |
| --- | --- |
| `packages/catalog-data/` | Live threat snapshots — JSON committed daily by CI |
| `packages/db/` | Drizzle schema shared between the pipeline and the web app |
| `packages/mvp-catalog/` | Stack registry — add a stack here to onboard it to the pipeline |
| `packages/mcp-server/` | MCP server (`@aigently/mcp-server`) — exposes catalog to AI agents |
| `packages/api-client/` | TypeScript client generated from the OpenAPI spec |
| `pipeline/scripts/` | `sync`, `amplify`, `summarize`, `synthesize`, `export` — the full pipeline |
| `.github/workflows/sync-threats.yml` | Weekly CI: ingest CVEs → AI guardrails → PR → merge |

---

## Threat intelligence pipeline

### Sources

The pipeline aggregates **five public threat sources** and normalizes them into a single schema:

| Source | What it contributes |
| --- | --- |
| **NVD** (NIST) | Authoritative CVE registry. Used for severity enrichment — fills in CVSS scores and CWE IDs after deduplication. |
| **CISA KEV** | US government list of CVEs actively exploited in the wild. Loaded first; sets `isActivelyExploited` as a hard prioritization signal. |
| **GHSA** (GitHub) | GitHub's advisory database across npm, pip, RubyGems, Maven, Go, Swift, and more. |
| **OSV** (Google) | Open-source vulnerability database. Queried per stack — only packages your configured stacks use. |
| **npm Audit** | Direct package advisory scan per stack. Catches advisories not yet reflected in OSV or GHSA. |

### How it flows

```text
Daily CI (GitHub Actions, 06:00 UTC):

  Ingest    npm Audit + OSV + GHSA → raw advisories
  Enrich    CISA KEV flags + NVD severity/CWE fill-in
  Filter    CVEs published after 2023-01-01 (CISA KEV always included)
  Persist   write threats + stack associations to Postgres

  Amplify   Claude: 2–4 ALWAYS/NEVER patterns per CVE
  Summarize Claude: cluster CVEs into per-stack rule docs
  Synthesize Claude: merge into pre-built guardrail blocks (patterns + deps)
  Export    write JSON snapshots to packages/catalog-data/

  Commit    auto-push catalog-data/ to this repo
```

### AI enrichment

Each new CVE goes through three Claude passes before it becomes an IDE rule:

1. **Amplify** — Claude generates 2–4 `ALWAYS`/`NEVER` statements specific to the CVE's attack vector plus a one-sentence risk summary.
2. **Summarize** — CVEs are clustered by attack vector into per-stack rule documents with ALWAYS/NEVER/WARN/CONFIRM directives.
3. **Synthesize** — Rules are merged per stack into two pre-built guardrail blocks: `patterns` (safe-coding directives) and `deps` (dependency advisories). One file per stack per type — rich and complete.

### Supported stacks

Next.js, Express, NestJS, Nuxt, React SPA, FastAPI, Django, Ruby on Rails, Go, iOS, Android.

Add a stack: open [`packages/mvp-catalog/src/stack-registry.ts`](packages/mvp-catalog/src/stack-registry.ts), add a `StackConfig` entry, open a PR.

---

## Quick start

No API keys needed — CI commits fresh snapshots weekly, just clone and use.

```bash
git clone https://github.com/aelbuni/aigently-catalog
cd aigently-catalog
npm install

cp pipeline/.env.example pipeline/.env   # default DATABASE_URL matches docker-compose
npm run db:setup                          # start Postgres, migrate, seed
```

### MCP server

Add to your IDE's MCP config (Claude Code, Cursor, Windsurf, Copilot, Cline):

```json
{
  "mcpServers": {
    "aigently": {
      "command": "npx",
      "args": ["-y", "@aigently/mcp-server@latest"]
    }
  }
}
```

The MCP server reads static JSON from `packages/catalog-data/` — no DB or API keys needed. Tools:

| Tool | What it does |
| --- | --- |
| `get_security_context` | Detect your stack + return relevant rules and top CVEs |
| `compose_guardrail` | Generate an IDE-ready rules file for your stack |
| `search_threats` | Full-text + faceted CVE search |
| `get_threat` | Full CVE detail + AI-generated patterns |
| `detect_project_stack` | Identify stack from file list |

---

## Run the full pipeline

```bash
# Add to pipeline/.env:
# ANTHROPIC_API_KEY=...   (amplify, summarize, synthesize)
# GITHUB_TOKEN=...        (GHSA source)
# NVD_API_KEY=...         (optional — 10× faster NVD enrichment)

npm run sync:threats           # ingest CVEs from all five sources
npm run amplify:threats        # Claude: ALWAYS/NEVER patterns per CVE
npm run summarize:rules        # Claude: cluster into per-stack rule docs
npm run synthesize:guardrails  # Claude: pre-build guardrail blocks
npm run export:catalog         # write JSON to packages/catalog-data/
```

---

## Reference

### Scripts

| Script | Purpose |
| --- | --- |
| `npm run db:up` | Start Postgres via Docker Compose |
| `npm run db:setup` | First-time: start Postgres + migrate + seed |
| `npm run db:migrate` | Apply Drizzle migrations |
| `npm run db:seed` | Full catalog seed |
| `npm run db:seed:upsert` | Non-destructive upsert |
| `npm run sync:threats` | Ingest CVEs from all five sources |
| `npm run amplify:threats` | AI-generate patterns for new threats |
| `npm run summarize:rules` | AI-cluster CVEs into rule summaries |
| `npm run synthesize:guardrails` | Pre-build per-stack guardrail blocks |
| `npm run export:catalog` | Export DB → `packages/catalog-data/` JSON |

### Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Yes | Postgres connection string |
| `ANTHROPIC_API_KEY` | AI steps | Claude API access |
| `GITHUB_TOKEN` | Sync | GitHub advisory source |
| `NVD_API_KEY` | Optional | 10× NVD rate limit |

---

## Contributing

PRs welcome. Highest-value contributions:

- **New stacks** — add to `packages/mvp-catalog/src/stack-registry.ts`
- **CVE curation** — improve `mustLines`, `ruleContext`, or `alwaysPin` in `packages/catalog-data/seed-master.json`
- **Pattern quality** — open an issue if an ALWAYS/NEVER line is wrong or too generic
- **New threat sources** — add a module under `pipeline/scripts/lib/sources/`

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## Prerequisites

- Node.js 22+
- Docker (for local Postgres)
- Anthropic API key (for AI pipeline steps only)

---

## License

Apache 2.0 — threat data sourced from public domain (NVD, CISA KEV, GHSA, OSV).

Aigent.ly and the Aigent.ly logo are trademarks of Aigently, Inc.
