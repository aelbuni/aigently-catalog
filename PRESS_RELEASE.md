# Press Release

**FOR IMMEDIATE RELEASE**
Berlin · 2026

# Aigent.ly Doubles Its Open-Source CVE Catalog: 12 Stacks, AI/LLM Coverage, and EPSS Exploit-Probability Scoring for AI Coding Assistants

> In one release, the catalog jumps from 6 to 12 supported stacks — adding Django, Ruby on Rails, Go, iOS/Swift, Android/Kotlin, and a brand-new **AI/LLM Apps** stack — and starts ranking every CVE by **how likely it is to be attacked**, not just how severe it is on paper.

---

## The story

Aigent.ly today released a major expansion of [aigently-catalog](https://github.com/aelbuni/aigently-catalog) — the open-source CVE pipeline that turns live threat intelligence into IDE-native guardrails for Claude Code, Cursor, Windsurf, GitHub Copilot, and Cline.

**Three changes ship together:**

### 1. Twelve live stacks, up from six

Five stacks already in the registry — **Django**, **Ruby on Rails**, **Go**, **iOS / Swift**, and **Android / Kotlin** — graduate from "coming soon" to fully live. Their CVE data has been quietly flowing through the pipeline; today they get first-class catalog status, MCP detection signals, and AI-generated IDE rules. Combined with the brand-new AI/LLM stack, that's a **100% jump in coverage in a single release**.

### 2. AI / LLM stack coverage

The catalog now ingests CVEs targeting **LangChain**, **LlamaIndex**, **Hugging Face transformers**, **llama-cpp-python**, **vLLM**, **Gradio**, **Ollama**, and 10+ other AI-application frameworks — classified against the **OWASP LLM Top 10** instead of the Web Top 10. Threats from this stack flow through a dedicated LLM-aware prompt in the amplifier so guardrails read like:

> *NEVER concatenate untrusted retrieval-augmented context directly into the system prompt.*
> *ALWAYS bound agent tools to an explicit allowlist of callable functions.*

…not generic web guardrails about CSRF and XSS. Developers building agents, RAG pipelines, and LLM-backed APIs now get the same just-in-time protection web developers have had for Next.js and FastAPI since launch.

### 3. EPSS exploit-probability scoring

Every CVE in the catalog now carries its **EPSS score** (Exploit Prediction Scoring System, FIRST.org) — a daily-updated probability that the vulnerability will be exploited in the next 30 days. AI assistants using the catalog now prioritize CVEs **the way attackers prioritize targets**, not the way auditors prioritize paperwork.

> *"CVSS tells you how bad a CVE is in a lab. EPSS tells you whether attackers are actually using it. The difference is the difference between a clean audit and a real breach."*
> — Aigent.ly maintainer

---

## Why this matters

AI coding assistants now write a meaningful share of production code. They are fast, fluent, and **uninformed** about which CVEs landed last week in the libraries they're importing. Static SAST tools catch issues at audit time, by which point the vulnerable code is already in the repo, in CI, and possibly in production.

Aigent.ly closes that loop: a daily GitHub Actions run pulls fresh CVEs from **NVD, CISA KEV, GHSA, OSV, npm Audit, and now EPSS** — has Claude generate `ALWAYS`/`NEVER` coding patterns per CVE — and commits the resulting rules straight into the repo, where any MCP-aware IDE picks them up at generation time.

With this release, the catalog covers the full surface where modern software actually gets built: the JavaScript front- and back-ends, the Python web layer, Ruby and Go services, mobile apps on iOS and Android, and — for the first time in any open MCP catalog we know of — **the AI stack itself**, where the AI is writing code that calls other AI. Self-hosting the guardrails for your own toolchain isn't a slogan; it's the architecture.

---

## What's in the box

- **12 application stacks live** (was 6): Next.js, Express/Node, FastAPI, NestJS, Nuxt, React SPA, Django, Ruby on Rails, Go, iOS/Swift, Android/Kotlin, and the new AI/LLM Apps stack.
- **6 data sources** (was 5): NVD, CISA KEV, GHSA, OSV, npm Audit, EPSS.
- Threat objects now expose `epssScore` and `epssPercentile` through the MCP `get_threat`, `search_threats`, and `get_security_context` tools.
- **`search_threats` ranks results** by KEV → severity → EPSS, putting the CVEs attackers are actively weaponizing at the top of the list.
- **Family-aware amplifier**: AI/LLM threats get an OWASP LLM Top 10 prompt instead of a web prompt — guardrails reflect the real attack surface.
- **Auto-detection**: drop a `langchain` or `llama-index` dependency into `requirements.txt` and the MCP server's `detect_project_stack` tool surfaces `ai-llm` guardrails automatically. Same for `Gemfile` (Rails), `go.mod` (Go), `Package.swift` (iOS), and `build.gradle` (Android).
- **Zero new API keys required.** EPSS is free at any scale.

---

## Availability

aigently-catalog is **Apache 2.0-licensed and free**. The catalog data, the ingestion pipeline, the stack registry, and the MCP server are all public. The hosted product at [aigent.ly](https://aigent.ly) remains private — the security boundary is by design.

- **GitHub:** [github.com/aelbuni/aigently-catalog](https://github.com/aelbuni/aigently-catalog)
- **MCP:** `npx -y @aigently/mcp-server@latest`
- **Product:** [aigent.ly](https://aigent.ly)

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

---

## About Aigent.ly

Aigent.ly is the security product that practices what it preaches. It turns live CVE intelligence into IDE-native guardrails so AI coding assistants stop reintroducing vulnerabilities the moment they're disclosed. **The data, pipeline, and rules are open source. The web app is private** — because a security product should hold itself to the standard it sells.

**Press contact:** press@aigent.ly
