export const CWE_PATTERN_LINES: Record<string, string[]> = {
  // A01 — Broken Access Control
  "CWE-284": [
    "NEVER trust request attributes (headers, params) as proof of authorization.",
    "ALWAYS apply access control checks in the route handler, not only in middleware.",
  ],
  "CWE-285": [
    "NEVER rely on client-provided role or permission claims without server-side verification.",
    "ALWAYS enforce authorization checks on the server at every route handler boundary.",
  ],
  "CWE-639": [
    "NEVER expose sequential or guessable object IDs in URLs without ownership checks.",
    "ALWAYS verify the authenticated user owns or is authorized to access the requested resource.",
  ],
  "CWE-863": [
    "NEVER skip authorization checks on the assumption that upstream middleware already validated the request.",
    "ALWAYS authorize at the resource level, not just at the route level.",
  ],
  "CWE-22": [
    "NEVER use user-controlled path segments without resolving and validating against a base directory.",
    "ALWAYS call path.resolve() and assert the result starts with the intended root before file operations.",
  ],
  "CWE-59": [
    "NEVER follow symlinks in user-controlled paths without resolving to a canonical path first.",
    "ALWAYS use fs.realpath() and validate the resolved path is within the expected directory.",
  ],
  // A02 — Cryptographic Failures
  "CWE-327": [
    "NEVER use MD5, SHA-1, DES, RC4, or other deprecated cryptographic algorithms.",
    "ALWAYS use modern algorithms: AES-GCM for encryption, SHA-256+ for hashing, Ed25519 for signing.",
  ],
  "CWE-326": [
    "NEVER use key sizes below the current minimum (RSA <2048-bit, EC <256-bit, AES <128-bit).",
    "ALWAYS select key sizes that meet or exceed current NIST recommendations.",
  ],
  "CWE-312": [
    "NEVER log, store, or transmit sensitive values (tokens, passwords, PII) in plaintext.",
    "ALWAYS encrypt sensitive fields at rest and in transit.",
  ],
  "CWE-311": [
    "NEVER transmit sensitive data over unencrypted channels.",
    "ALWAYS enforce HTTPS and validate TLS configuration for all endpoints handling sensitive data.",
  ],
  "CWE-330": [
    "NEVER use Math.random() or other non-cryptographic sources for security-sensitive values.",
    "ALWAYS use crypto.randomBytes() or the Web Crypto API for tokens, nonces, and session IDs.",
  ],
  "CWE-295": [
    "NEVER disable TLS certificate verification in any environment.",
    "ALWAYS configure your HTTP client to verify the full certificate chain.",
  ],
  // A03 — Injection
  "CWE-89": [
    "NEVER interpolate user input directly into SQL strings.",
    "ALWAYS use parameterized queries or an ORM query builder for all database operations.",
  ],
  "CWE-79": [
    "NEVER render user-controlled strings as raw HTML without escaping.",
    "ALWAYS sanitize untrusted content before injecting into the DOM or template output.",
  ],
  "CWE-78": [
    "NEVER construct shell commands from user input.",
    "ALWAYS use execFile() with an explicit argument array instead of exec() with string interpolation.",
  ],
  "CWE-94": [
    "NEVER evaluate or execute user-supplied code strings.",
    "ALWAYS use safe alternatives to eval(), Function(), and dynamic require().",
  ],
  "CWE-20": [
    "NEVER pass user input to internal APIs without validation and normalization.",
    "ALWAYS define an explicit allowlist of expected values and reject anything outside it.",
  ],
  "CWE-1321": [
    "NEVER merge untrusted objects into configs without guarding against prototype keys.",
    "ALWAYS sanitize user-controlled JSON and use Object.create(null) for accumulator objects.",
  ],
  "CWE-77": [
    "NEVER concatenate user input into command strings passed to any shell interpreter.",
    "ALWAYS use structured argument arrays and avoid shell: true in child_process options.",
  ],
  "CWE-917": [
    "NEVER pass user-controlled strings to expression language engines without escaping.",
    "ALWAYS treat template and EL input as untrusted and apply context-appropriate encoding.",
  ],
  "CWE-74": [
    "NEVER insert user-controlled data into structured formats (HTML, SQL, XML, JSON) without encoding.",
    "ALWAYS use the output encoding function appropriate to the injection context.",
  ],
  // A04 — Insecure Design
  "CWE-915": [
    "NEVER use mass assignment to bind request bodies directly to model objects without an allowlist.",
    "ALWAYS define explicit field allowlists for any object populated from user-controlled input.",
  ],
  "CWE-434": [
    "NEVER accept uploaded files without validating type, size, and content against an allowlist.",
    "ALWAYS store uploads outside the web root and serve via a controlled download endpoint.",
  ],
  // A05 — Security Misconfiguration
  "CWE-798": [
    "NEVER hard-code secrets, API keys, or credentials in source files.",
    "ALWAYS load secrets from environment variables or a secrets manager at runtime.",
  ],
  "CWE-116": [
    "NEVER pass unencoded output into HTML, shell, or SQL contexts.",
    "ALWAYS encode data for the specific output context before rendering or executing.",
  ],
  "CWE-942": [
    "NEVER configure CORS with a wildcard origin on endpoints that accept credentials.",
    "ALWAYS restrict CORS origins to an explicit allowlist and validate on every request.",
  ],
  "CWE-346": [
    "NEVER trust the Origin header alone for CORS decisions on credentialed requests.",
    "ALWAYS validate Origin against an explicit allowlist and pair with CSRF protection.",
  ],
  "CWE-732": [
    "NEVER create files or directories with world-writable permissions.",
    "ALWAYS apply the principle of least privilege when setting file system permissions.",
  ],
  "CWE-16": [
    "NEVER leave default credentials, debug endpoints, or verbose error messages enabled in production.",
    "ALWAYS audit configuration before deployment and use environment-specific config files.",
  ],
  // A06 — Vulnerable and Outdated Components
  "CWE-400": [
    "NEVER process unbounded user-controlled input in regex, parsers, or loops without size limits.",
    "ALWAYS apply strict length and rate limits to all user-controlled data before processing.",
  ],
  "CWE-1104": [
    "NEVER include third-party components without verifying they are actively maintained and patched.",
    "ALWAYS pin dependencies to exact versions and monitor for known vulnerabilities in your supply chain.",
  ],
  // A07 — Identification and Authentication Failures
  "CWE-287": [
    "NEVER skip re-authentication for sensitive operations even when a session already exists.",
    "ALWAYS verify identity at the point of sensitive action, not only at login.",
  ],
  "CWE-306": [
    "NEVER expose sensitive functionality without requiring authentication.",
    "ALWAYS gate every sensitive operation behind an authentication check.",
  ],
  "CWE-307": [
    "NEVER allow unlimited login or verification attempts without rate limiting.",
    "ALWAYS implement account lockout or exponential backoff after repeated failed attempts.",
  ],
  "CWE-521": [
    "NEVER accept passwords without enforcing minimum length and complexity requirements.",
    "ALWAYS apply password policy on the server side, never only on the client.",
  ],
  // A08 — Software and Data Integrity Failures
  "CWE-502": [
    "NEVER deserialize user-supplied data with a permissive deserializer.",
    "ALWAYS validate schema and type before deserializing untrusted payloads.",
  ],
  "CWE-352": [
    "NEVER accept state-changing requests without CSRF token validation.",
    "ALWAYS use framework-provided CSRF middleware on all mutating endpoints.",
  ],
  "CWE-494": [
    "NEVER load or execute code from user-controlled URLs or paths.",
    "ALWAYS use a content integrity mechanism (SRI, signature verification) for all loaded assets.",
  ],
  // A09 — Security Logging and Monitoring Failures
  "CWE-532": [
    "NEVER include sensitive data (tokens, PII, secrets) in log output.",
    "ALWAYS scrub or redact sensitive fields before passing objects to loggers.",
  ],
  "CWE-778": [
    "NEVER omit logging for security-relevant events (auth failures, permission denials, unusual inputs).",
    "ALWAYS log the who, what, and when for every security-relevant action in a tamper-resistant store.",
  ],
  // A10 — SSRF
  "CWE-918": [
    "NEVER fetch attacker-controlled URLs from server-side code.",
    "ALWAYS validate outbound request hostnames against an explicit allowlist before making requests.",
  ],
  // LLM-specific
  "CWE-200": [
    "NEVER include sensitive system details, credentials, or PII in prompts sent to external models.",
    "ALWAYS sanitize and audit prompt content before sending to any external AI service.",
  ],
};

/**
 * Returns ALWAYS/NEVER pattern lines for the first CWE in the given list
 * that has a known pattern. Use the stack's cwePriority as the input.
 */
export function getCwePatternLines(cwes: string[]): string[] {
  for (const cwe of cwes) {
    const lines = CWE_PATTERN_LINES[cwe];
    if (lines && lines.length > 0) return lines;
  }
  return [];
}
