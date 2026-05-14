const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

interface NvdVuln {
  cve: {
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData?: { baseScore: number; baseSeverity: string };
      }>;
    };
    weaknesses?: Array<{
      description: Array<{ value: string }>;
    }>;
    references?: Array<{ url: string }>;
  };
}

export interface NvdEnrichment {
  cvssScore:   number | null;
  rawSeverity: string | null;
  cweIds:      string[];
  references:  string[];
}

export async function enrichFromNvd(
  cveId:  string,
  apiKey?: string
): Promise<NvdEnrichment | null> {
  const headers: Record<string, string> = {};
  if (apiKey) headers["apiKey"] = apiKey;

  const url = `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`;
  const res = await fetch(url, { headers });
  if (!res.ok) return null;

  const data = await res.json() as { vulnerabilities?: NvdVuln[] };
  const vuln = data.vulnerabilities?.[0];
  if (!vuln) return null;

  const cve     = vuln.cve;
  const metrics = cve.metrics?.cvssMetricV31?.[0];
  const cwes    = cve.weaknesses?.flatMap(w =>
    w.description.map(d => d.value).filter(v => v.startsWith("CWE-"))
  ) ?? [];

  return {
    cvssScore:   metrics?.cvssData?.baseScore ?? null,
    rawSeverity: metrics?.cvssData?.baseSeverity ?? null,
    cweIds:      cwes,
    references:  cve.references?.map(r => r.url) ?? [],
  };
}
