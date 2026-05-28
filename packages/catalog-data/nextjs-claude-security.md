# Aigent.ly — Nextjs Security Guardrails v1.0

Built from live CVE data · **18 threats covered**

OWASP coverage: A01, A02, A03, A06, A07, A08, A10

## Covered CVEs

```text
CVE-2025-29927            [CRITICAL] Authorization Bypass in Next.js Middleware
CVE-2022-0235             [HIGH    ] node-fetch forwards secure headers to untrusted sites
CVE-2024-34351            [HIGH    ] Next.js Server-Side Request Forgery in Server Actions
CVE-2022-23539            [HIGH    ] jsonwebtoken unrestricted key type could lead to legacy
CVE-2024-46982            [HIGH    ] Next.js Cache Poisoning
CVE-2021-3749             [HIGH    ] axios Inefficient Regular Expression Complexity vulnera
CVE-2021-23337            [HIGH    ] Command Injection in lodash
CVE-2024-51479            [HIGH    ] Next.js authorization bypass vulnerability
CVE-2025-27152            [HIGH    ] axios Requests Vulnerable To Possible SSRF and Credenti
GHSA-npm-1111391          [HIGH    ] Next Vulnerable to Denial of Service with Server Compon
GHSA-npm-1112182          [HIGH    ] Next has a Denial of Service with Server Components - I
GHSA-npm-1112653          [HIGH    ] Next.js HTTP request deserialization can lead to DoS wh
CVE-2026-25639            [HIGH    ] Axios is Vulnerable to Denial of Service via __proto__
CVE-2026-4800             [HIGH    ] lodash vulnerable to Code Injection via `_.template` im
GHSA-npm-1116376          [HIGH    ] Next.js has a Denial of Service with Server Components
CVE-2026-42043            [HIGH    ] Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Pro
CVE-2026-42033            [HIGH    ] Axios: Prototype Pollution Gadgets - Response Tampering
CVE-2026-42035            [HIGH    ] Axios: Header Injection via Prototype Pollution
```

## A01 — Broken Access Control

### Prevents CVE-2024-46982: Next.js Cache Poisoning
Context: Crafted requests can poison cached HTML for some Pages Router SSR routes (not App Router). Treat as broken access / cache integrity until patched.

MUST: Apply vendor patches before relying on caching semantics for SSR HTML.

Upgrade to version 14.2.10 or later.
ALWAYS use patched version: next >=14.2.10

### Prevents CVE-2024-51479: Next.js authorization bypass vulnerability
Context: Authorization enforced only in middleware using pathname checks could be bypassed on vulnerable Next.js builds.

MUST: Patch Next.js and add defense-in-depth checks beyond pathname-only middleware.

Upgrade to version 14.2.15 or later.
ALWAYS use patched version: next >=14.2.15

### Prevents CVE-2025-29927: Authorization Bypass in Next.js Middleware
Context: Critical middleware authorization bypass via crafted requests on affected Next.js trains (patch matrix per advisory).

MUST: Upgrade Next.js immediately on affected lines and redeploy.

Upgrade to version 14.2.25 or later.
ALWAYS use patched version: next >=14.2.25

## A02 — Cryptographic Failures

### Prevents CVE-2022-0235: node-fetch forwards secure headers to untrusted sites
Context: Redirect handling can forward sensitive headers such as Authorization and cookies to untrusted origins.

MUST: Upgrade node-fetch and avoid privileged redirects you do not fully control.

Upgrade to version 2.6.7 or later.
ALWAYS use patched version: node-fetch >=2.6.7

## A03 — Injection

### Prevents CVE-2021-23337: Command Injection in lodash
Context: Older lodash `_.template` can enable command injection via malicious templates.

MUST: Upgrade lodash off vulnerable template-era releases.

Upgrade to version 4.17.21 or later.
ALWAYS use patched version: lodash >=4.17.21

### Prevents CVE-2026-4800: lodash vulnerable to Code Injection via `_.template` imports key names
Context: Follow-on hardening gap after CVE-2021-23337 around `_.template` imports/options enables further code injection.

MUST: Upgrade lodash to releases containing this fix.

Upgrade to version 4.18.0 or later.
ALWAYS use patched version: lodash >=4.18.0

## A06 — Outdated Components

### Prevents CVE-2021-3749: axios Inefficient Regular Expression Complexity vulnerability
Context: Axios versions before 0.21.2 have ReDoS risk from unsafe regex handling.

MUST: Upgrade axios.

Upgrade to version 0.21.2 or later.
ALWAYS use patched version: axios >=0.21.2

### Prevents GHSA-npm-1111391: Next Vulnerable to Denial of Service with Server Components
Context: DoS conditions affecting certain React 19 packages used by Next.js Server Components.

MUST: Patch Next.js/React combinations per advisory.

Upgrade to version 14.2.34 or later.
ALWAYS use patched version: next >=14.2.34

### Prevents GHSA-npm-1112182: Next has a Denial of Service with Server Components - Incomplete Fix Follow-Up
Context: Prior Server Components DoS mitigation was incomplete; additional patched builds required.

MUST: Apply follow-on patched releases.

Upgrade to version 14.2.35 or later.
ALWAYS use patched version: next >=14.2.35

### Prevents GHSA-npm-1112653: Next.js HTTP request deserialization can lead to DoS when using insecure React Server Components
Context: Malformed request deserialization can exhaust resources when insecure RSC pathways are exposed.

MUST: Upgrade Next.js and narrow exposed Server Components surface area.

Upgrade to version 15.0.8 or later.
ALWAYS use patched version: next >=15.0.8

## A07 — Authentication Failures

### Prevents CVE-2022-23539: jsonwebtoken unrestricted key type could lead to legacy keys usage 
Context: Misconfiguration allows legacy/insecure key types during JWT verification.

MUST: Upgrade jsonwebtoken and explicitly restrict algorithms and key material.

Upgrade to version 9.0.0 or later.
ALWAYS use patched version: jsonwebtoken >=9.0.0

## A08 — Integrity Failures / CSRF

Response integrity for SSR relies on safe caching and patching; CVE-2024-46982 (see **A01**) covers cache poisoning—pair patches with strict cache-control discipline on sensitive routes.

## A10 — SSRF

### Prevents CVE-2024-34351: Next.js Server-Side Request Forgery in Server Actions
Context: SSRF via manipulated Host header flows through Server Actions under advisory conditions.

MUST: Patch Next.js and validate outbound assumptions for Actions.

Upgrade to version 14.1.1 or later.
ALWAYS use patched version: next >=14.1.1

### Prevents CVE-2025-27152: axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL
Context: Absolute URLs and redirects can surface SSRF or credential leakage in axios.

MUST: Upgrade axios and constrain hosts and redirect handling.

Upgrade to version 0.30.0 or later.
ALWAYS use patched version: axios >=0.30.0

### Prevents CVE-2026-42043: Axios: Incomplete Fix for CVE-2025-62718 — NO_PROXY Protection Bypassed via RFC 1122 Loopback Subnet (127.0.0.0/8) in Axios 1.15.0
Context: Incomplete NO_PROXY handling left SSRF-style routing gadgets after prior fixes.

MUST: Upgrade axios beyond vulnerable builds.

Upgrade to version 0.31.1 or later.
ALWAYS use patched version: axios >=0.31.1

## MISC — General

### Prevents CVE-2026-25639: Axios is Vulnerable to Denial of Service via __proto__ Key in mergeConfig
Context: Crash/DoS when mergeConfig encounters polluted `__proto__` keys.

MUST: Upgrade axios.

Upgrade to version 0.30.3 or later.
ALWAYS use patched version: axios >=0.30.3

### Prevents GHSA-npm-1116376: Next.js has a Denial of Service with Server Components
Context: Additional Server Components DoS vectors across Next.js trains using App Router.

MUST: Upgrade Next.js per advisory.

Upgrade to version 15.5.15 or later.
ALWAYS use patched version: next >=15.5.15

### Prevents CVE-2026-42033: Axios: Prototype Pollution Gadgets - Response Tampering, Data Exfiltration, and Request Hijacking
Context: When prototype pollution exists in the dependency graph, axios can amplify impact via JSON/response gadget chains.

MUST: Upgrade axios and audit pollution risks upstream.

Upgrade to version 0.31.1 or later.
ALWAYS use patched version: axios >=0.31.1

### Prevents CVE-2026-42035: Axios: Header Injection via Prototype Pollution
Context: Pollution gadgets may inject unexpected HTTP headers on outbound axios requests.

MUST: Upgrade axios.

Upgrade to version 0.31.1 or later.
ALWAYS use patched version: axios >=0.31.1

## DO NOT — highest blast radius patterns for this stack

1. DO NOT: rely on pathname-only middleware authorization without patched Next.js (CVE-2025-29927, CVE-2024-51479).
2. DO NOT: let node-fetch follow redirects with privileged credentials without patching header-forwarding behavior (CVE-2022-0235).
3. DO NOT: expose Server Actions where attacker-controlled Host can steer requests without patched Next.js (CVE-2024-34351).
4. DO NOT: verify JWTs using permissive legacy algorithms or outdated jsonwebtoken configurations (CVE-2022-23539).
5. DO NOT: ship vulnerable Pages Router SSR caching paths susceptible to cache poisoning without mitigation (CVE-2024-46982).
