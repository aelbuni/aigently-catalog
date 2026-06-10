const EPSS_BASE = "https://api.first.org/data/v1/epss";
const CHUNK_SIZE = 50;
const CHUNK_DELAY_MS = 100;

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

export interface EpssEntry {
  score: number;
  percentile: number;
}

interface EpssApiRow {
  cve: string;
  epss: string;
  percentile: string;
}

interface EpssApiResponse {
  status?: string;
  data?: EpssApiRow[];
}

export async function fetchEpssBatch(
  cveIds: string[]
): Promise<Map<string, EpssEntry>> {
  const map = new Map<string, EpssEntry>();
  if (cveIds.length === 0) return map;

  const unique = [...new Set(cveIds)];

  for (let i = 0; i < unique.length; i += CHUNK_SIZE) {
    const chunk = unique.slice(i, i + CHUNK_SIZE);
    const url   = `${EPSS_BASE}?cve=${encodeURIComponent(chunk.join(","))}`;

    try {
      const res = await fetch(url);
      if (!res.ok) {
        console.error(`EPSS fetch failed (chunk ${i / CHUNK_SIZE}): ${res.status}`);
        continue;
      }

      const data = await res.json() as EpssApiResponse;
      for (const row of data.data ?? []) {
        const score      = Number(row.epss);
        const percentile = Number(row.percentile);
        if (Number.isFinite(score) && Number.isFinite(percentile)) {
          map.set(row.cve, { score, percentile });
        }
      }
    } catch (e) {
      console.error(`EPSS fetch error (chunk ${i / CHUNK_SIZE}):`, e);
    }

    if (i + CHUNK_SIZE < unique.length) await sleep(CHUNK_DELAY_MS);
  }

  return map;
}
