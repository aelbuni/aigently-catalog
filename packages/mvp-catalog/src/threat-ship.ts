import { REAL_GHSA_PUBLIC_IDS } from "./launch.js";

const CVE_RE = /^CVE-\d{4}-\d+$/i;
/** Real GitHub advisory id shape (not placeholders like GHSA-npm-1111391). */
const REAL_GHSA_RE = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/i;
const PLACEHOLDER_GHSA_RE = /^GHSA-npm-\d+$/i;
const SYNTHETIC_PREFIXES = [
  "DJANGO-CWE-",
  "RAILS-CWE-",
  "GO-CWE-",
  "IOS-CWE-",
  "AND-CWE-",
  "MEM-",
  "SLOP-",
];

export type ShipCheckInput = {
  publicId: string;
  cveId?: string | null;
  sourceUrl?: string | null;
};

/**
 * Threat rows we persist and show: verifiable CVE or real GHSA id,
 * with a non-empty HTTP(S) source URL. Drops synthetic pattern IDs and placeholder GHSAs.
 */
export function isShippableThreat(t: ShipCheckInput): boolean {
  const url = (t.sourceUrl ?? "").trim();
  if (!url.startsWith("http://") && !url.startsWith("https://")) return false;

  const pid = t.publicId.trim();
  const cve = (t.cveId ?? "").trim();

  if (SYNTHETIC_PREFIXES.some((p) => pid.startsWith(p))) return false;
  if (PLACEHOLDER_GHSA_RE.test(pid)) return false;

  if (CVE_RE.test(cve)) return true;
  if (CVE_RE.test(pid)) return true;
  if (REAL_GHSA_RE.test(pid)) return true;
  return REAL_GHSA_PUBLIC_IDS.has(pid);
}
