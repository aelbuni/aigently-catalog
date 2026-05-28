const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export interface KevEntry {
  dueDate: string | null;
}

export async function fetchKevMap(): Promise<Map<string, KevEntry>> {
  const res  = await fetch(KEV_URL);
  if (!res.ok) throw new Error(`CISA KEV fetch failed: ${res.status}`);
  const data = await res.json() as { vulnerabilities: Array<{ cveID: string; dueDate?: string }> };

  const map = new Map<string, KevEntry>();
  for (const v of data.vulnerabilities) {
    map.set(v.cveID, { dueDate: v.dueDate ?? null });
  }
  return map;
}
