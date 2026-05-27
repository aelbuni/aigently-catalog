# Security Policy

## Supported Versions

The catalog pipeline and MCP server track the latest `main` branch. Only the current release receives security fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/aelbuni/aigently-catalog/security/advisories/new).

Include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected versions or components
- Suggested remediation if known

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days**.

## Scope

| Component | In Scope |
|-----------|----------|
| MCP server (`packages/mcp-server`) | Yes |
| Pipeline scripts (`pipeline/scripts`) | Yes |
| Catalog data (`packages/catalog-data`) | No — read-only public data |
| Third-party dependencies | Only if exploitable via this repo |

## Security Controls

- All 30 database tables have Row-Level Security (RLS) enabled — unauthenticated callers receive zero rows
- Secrets are injected at runtime via environment variables — no credentials are committed to this repo
- Dependabot monitors all npm dependencies weekly and opens PRs for vulnerable packages
- CodeQL scans every push and pull request for code-level security issues

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). Once a fix is available and deployed we will credit the reporter (unless they prefer to remain anonymous) in the release notes.
