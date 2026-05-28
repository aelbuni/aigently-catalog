# Contributing to aigently-catalog

Thanks for helping improve the security catalog. There are three ways to contribute.

---

## 1. Add a new stack

Open [`packages/mvp-catalog/src/stack-registry.ts`](packages/mvp-catalog/src/stack-registry.ts) and add a `StackConfig` entry with the stack's ecosystem, package list, and CVE sources. Then open a PR — the pipeline will automatically sync CVEs, generate AI patterns, and create rules when the PR merges.

## 2. Improve CVE curation

Manual overrides live in [`packages/catalog-data/seed-master.json`](packages/catalog-data/seed-master.json). You can improve:

- `mustLines` — explicit ALWAYS/NEVER statements that replace AI-generated patterns
- `ruleContext` — a one-sentence plain-English description of the real-world risk
- `alwaysPin` — force a threat to always be included in a stack's rules

Open a PR with your changes and describe why the override is more accurate than the AI-generated version.

## 3. Improve the MCP server

Standard fork → branch → PR flow.

```bash
npm install
npm run build -w @aigently/mcp-server
npm test -w @aigently/mcp-server   # all tests must pass
```

Source is in [`packages/mcp-server/src/`](packages/mcp-server/src/). See [DEVELOPMENT.md](DEVELOPMENT.md) for the full local setup guide.

---

## Guidelines

- Keep PRs focused — one stack, one CVE fix, or one server change per PR
- For pattern quality issues, open an issue first describing what's wrong and why
- The pipeline is automated — do not hand-edit `threats.json`, `rules.json`, or `guardrails.json` directly; those are generated outputs

## License

By contributing, you agree your contributions are licensed under [Apache 2.0](LICENSE).
