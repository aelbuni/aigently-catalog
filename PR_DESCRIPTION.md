## Summary

This PR ships three independent improvements:

1. **EPSS exploit-probability scoring** — every CVE in the catalog now carries a `epssScore` and `epssPercentile` field, sourced from FIRST.org's daily feed (no API key required). The MCP ranking formula promotes CVEs above the 0.5 and 0.9 thresholds.
2. **6 new stacks** — Django, Rails, Go, iOS/Swift, Android/Kotlin, and a brand-new **AI / LLM Apps** stack covering LangChain, LlamaIndex, Hugging Face, vLLM, Ollama, and 12+ other packages. The LLM stack maps threats against OWASP LLM Top 10 instead of the Web Top 10.
3. **Pipeline & workflow housekeeping** — manual-only CI trigger, refreshed README with inline demo video.

---

## Changes

### New: EPSS enrichment source (`pipeline/scripts/lib/sources/epss.ts`)
- Fetches the FIRST.org daily EPSS CSV in a single request and builds an in-memory lookup map
- Batched 50 CVEs per request to stay inside rate limits (1 000 req/min, no key required)
- `epssScore` (0–1 float) and `epssPercentile` (0–100) added to the `Threat` type, DB schema, and export

### New: 6 stacks (`packages/mvp-catalog/src/stack-registry.ts`)
| Stack | Family |
|---|---|
| Django | owasp_web |
| Ruby on Rails | owasp_web |
| Go | owasp_web |
| iOS / Swift | owasp_web |
| Android / Kotlin | owasp_web |
| **AI / LLM Apps** | **owasp_llm** |

- `ai-llm` stack watches 17 PyPI packages and classifies CVEs against LLM01–LLM10
- `amplify-threats.ts` uses a family-aware prompt: LLM stacks get OWASP LLM vocabulary in the generated guardrails
- `normalise.ts` extended with LLM CWE → OWASP LLM Top 10 mapping

### MCP server updates (`packages/mcp-server/`)
- `get_security_context`, `search_threats`, and `get_threat` now return `epssScore` / `epssPercentile`
- `search_threats` ranking: KEV → severity → EPSS ≥ 0.9 (+2) / ≥ 0.5 (+1) → family → intent
- `detect_project_stack` extended to recognise Go, iOS, Android, and LLM package manifests

### DB migration (`pipeline/drizzle/0004_add_epss_columns.sql`)
- Adds `epss_score REAL` and `epss_percentile REAL` columns to the `threats` table (nullable, non-breaking)

### CI: manual-only trigger (`.github/workflows/sync-threats.yml`)
- Removed the `schedule: cron` block — the pipeline now runs only on `workflow_dispatch`
- Keeps the `force_summarize` input for full re-summarization runs

### README & demo
- Replaced broken asciinema embed with a native GitHub-rendered MP4 (`brand/aigently-mcp-demo.mp4`, 671 KB)
- Updated stack table, source table, pipeline diagram, and threat-prioritization formula to reflect EPSS and new stacks

---

## Test plan

- [ ] `npm run sync:threats` completes without errors; `epss_score` values appear in the DB for CVEs with known IDs
- [ ] `npm run amplify:threats` — threats in the `ai-llm` stack receive LLM-vocabulary guardrails (check for "prompt injection" / "retrieval context" phrasing)
- [ ] `npm run export:catalog` — exported JSON includes `epssScore` and `epssPercentile` on threat objects
- [ ] MCP tool `search_threats` returns results ordered correctly: KEV first, then EPSS ≥ 0.9 ahead of lower scores
- [ ] MCP tool `detect_project_stack` identifies `requirements.txt` containing `langchain` as `ai-llm`
- [ ] GitHub Actions: workflow no longer appears in the scheduled runs list; "Run workflow" button is present
- [ ] README video plays inline on GitHub (navigate to the repo root and confirm the `<video>` tag renders)

---

## Breaking changes

None. The EPSS columns are nullable; existing consumers that don't read those fields are unaffected. The new stacks are additive.
