# Aigent.ly Catalog

**Prevention-layer security for the vibe coding era.** The open-source CVE catalog and pipeline that powers [aigent.ly](https://aigent.ly).

This repo contains everything the community needs to run, extend, and contribute to the security rules catalog. The hosted web application at aigent.ly is a separate private repo — the catalog is the community asset.

> "We open-sourced everything the community needs — the data, the pipeline, the stack registry.  
> The web app that runs aigent.ly is private. Because a security product should practice what it preaches."

---

## What's here

| Path | Contents |
|---|---|
| `packages/catalog-data/` | CVE threat snapshots — JSON committed daily by CI |
| `packages/db/` | Drizzle schema shared between pipeline and app |
| `packages/mvp-catalog/` | Stack registry — add a stack here to include it in the pipeline |
| `packages/api-client/` | TypeScript client generated from the OpenAPI spec |
| `pipeline/scripts/` | sync, seed, amplify, summarize, export — the full CVE pipeline |
| `.github/workflows/sync-threats.yml` | Daily CI: fetch CVEs → AI guardrails → export JSON |

## What's not here

The web application (Next.js UI, auth, API server). That's private. The catalog is the open part.

---

## Quick start — no API keys needed

The daily CI pipeline commits fresh CVE data to `packages/catalog-data/` — cloning this repo gives you the latest threat data without running any pipeline scripts.

```bash
git clone https://github.com/aelbuni/aigently-catalog
cd aigently-catalog
npm install

# Copy env template and set DATABASE_URL (default matches docker-compose)
cp pipeline/.env.example pipeline/.env

# Start Postgres, run migrations, seed from catalog-data/ JSON
npm run db:setup

# Browse rules at localhost:3000 (requires the web app — see aigent.ly)
```

---

## Run the full CVE pipeline

To fetch fresh CVEs, generate AI guardrails, and export:

```bash
# Add to pipeline/.env:
# ANTHROPIC_API_KEY=...   (required for amplify + summarize)
# NVD_API_KEY=...         (optional, 10x faster NVD sync)
# GITHUB_TOKEN=...        (required for GHSA source)

npm run sync:threats       # fetch CVEs from NVD, CISA KEV, GHSA, OSV, npm
npm run amplify:threats    # Claude generates ALWAYS/NEVER patterns per CVE
npm run summarize:rules    # Claude clusters CVEs into attack-vector summaries
npm run export:catalog     # write JSON snapshots back to packages/catalog-data/
```

See [`pipeline/.env.example`](pipeline/.env.example) for all variables.

---

## Adding a stack

1. Open [`packages/mvp-catalog/src/stack-registry.ts`](packages/mvp-catalog/src/stack-registry.ts)
2. Add a `StackConfig` entry with the stack's ecosystem, package list, and CVE sources
3. Run the pipeline — threats will be synced, patterns generated, and rules created automatically
4. Open a PR

---

## How the pipeline works

```
Daily at 06:00 UTC (GitHub Actions):

sync:threats     ← NVD + CISA KEV + GHSA + OSV + npm audit
     ↓
amplify:threats  ← Claude: ALWAYS/NEVER patterns per CVE
     ↓
summarize:rules  ← Claude: cluster CVEs by attack-vector theme
     ↓
export:catalog   ← write JSON to packages/catalog-data/
     ↓
git commit+push  ← catalog data is the repo, not just a build artifact
```

---

## Scripts

| Script | Purpose |
|---|---|
| `npm run db:up` | Start Postgres via Docker Compose |
| `npm run db:setup` | First-time setup: start Postgres, migrate, seed |
| `npm run db:seed` | Full catalog seed from `catalog-data/` JSON |
| `npm run db:seed:upsert` | Non-destructive upsert (for iterative runs) |
| `npm run sync:threats` | Fetch CVEs from all sources |
| `npm run amplify:threats` | AI-generate patterns for unamplified threats |
| `npm run summarize:rules` | AI-cluster CVEs into summaries (FORCE=1 to overwrite) |
| `npm run export:catalog` | Export DB → `packages/catalog-data/` JSON |

---

## Prerequisites

- Node.js 20+
- Docker (for local Postgres)
- Anthropic API key (for `amplify:threats` and `summarize:rules` only)

---

## Contributing

PRs welcome. The highest-value contributions:

- **New stacks** — add to `packages/mvp-catalog/src/stack-registry.ts`
- **CVE curation** — improve `mustLines`, `ruleContext`, or `alwaysPin` overrides in `packages/catalog-data/seed-master.json`
- **Pattern quality** — open an issue if an ALWAYS/NEVER line is wrong or too generic

---

## License

Apache 2.0 — threat data sourced from public domain (NVD, CISA KEV, GHSA, OSV).
