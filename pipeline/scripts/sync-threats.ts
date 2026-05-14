import "../lib/load-env"; // loads pipeline/.env

import { STACK_REGISTRY } from "@aigently/mvp-catalog";
import { db, stack, pool } from "../lib/db";

import { fetchKevMap }                          from "./lib/sources/cisa-kev";
import { fetchNpmAdvisories, normaliseNpmAdvisory } from "./lib/sources/npm-audit";
import { fetchOsvForPackage, normaliseOsvVuln } from "./lib/sources/osv";
import { fetchGhsaForEcosystem, normaliseGhsa } from "./lib/sources/ghsa";
import { enrichFromNvd }                        from "./lib/sources/nvd";
import { mapCwesToOwasp, normaliseSeverity, deduplicateThreats } from "./lib/normalise";
import {
  upsertThreat,
  upsertThreatStack,
  refreshMitigationFlags,
  openSyncLog,
  closeSyncLog,
} from "./lib/upsert";
import type { NormalisedThreat, SyncSummary } from "./lib/types";

const STACK_FILTER = process.env.STACK_FILTER;
const DRY_RUN      = process.env.DRY_RUN === "true";
const sleep        = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

const configs = STACK_FILTER
  ? STACK_REGISTRY.filter(c => c.slug === STACK_FILTER)
  : STACK_REGISTRY;

function sourceKey(
  source: NormalisedThreat["source"]
): keyof Pick<SyncSummary, "npm_audit" | "osv" | "ghsa"> {
  if (source === "ghsa") return "ghsa";
  if (source === "osv")  return "osv";
  return "npm_audit";
}

async function main() {
  const logId  = await openSyncLog();
  const counts: SyncSummary = {
    npm_audit: { fetched: 0, upserted: 0, skipped: 0, errors: 0 },
    osv:       { fetched: 0, upserted: 0, skipped: 0, errors: 0 },
    ghsa:      { fetched: 0, upserted: 0, skipped: 0, errors: 0 },
    nvd:       { fetched: 0, upserted: 0, skipped: 0, errors: 0 },
    cisa_kev:  { totalKev: 0, newlyFlagged: 0 },
  };

  try {
    // ── Phase 0: Preflight ────────────────────────────────────────────
    console.log("Phase 0: loading CISA KEV and stack config...");
    const kevMap = await fetchKevMap();
    counts.cisa_kev.totalKev = kevMap.size;
    console.log(`  → KEV map loaded: ${kevMap.size} entries`);

    const stacks     = await db.select().from(stack);
    const stackIdMap = new Map(stacks.map(s => [s.slug, s.id] as [string, number]));
    console.log(`  → ${stacks.length} stacks loaded from DB`);

    const rawThreats: NormalisedThreat[] = [];

    // ── Phase 1: npm Audit ────────────────────────────────────────────
    for (const config of configs) {
      if (!config.npmPackages) continue;
      console.log(`Phase 1 [npm-audit]: ${config.slug}`);
      try {
        const advisories = await fetchNpmAdvisories(config.npmPackages);
        counts.npm_audit.fetched += advisories.length;
        for (const adv of advisories) {
          const t = normaliseNpmAdvisory(adv, config.slug, config, kevMap);
          if (t) rawThreats.push(t);
          else   counts.npm_audit.skipped++;
        }
      } catch (e) {
        counts.npm_audit.errors++;
        console.error(`npm-audit error for ${config.slug}:`, e);
      }
    }

    // ── Phase 2: OSV — deduplicated (package, ecosystem) pairs ────────
    console.log("Phase 2 [osv]: building deduplicated package query set...");
    const osvQueries = new Map<string, string[]>(); // "pkg::eco" → [slugs]
    for (const config of configs) {
      for (const pkg of config.osvPackages) {
        const key   = `${pkg}::${config.osvEcosystem}`;
        const slugs = osvQueries.get(key) ?? [];
        slugs.push(config.slug);
        osvQueries.set(key, slugs);
      }
    }
    console.log(`  → ${osvQueries.size} unique (package, ecosystem) queries`);

    for (const [key, slugs] of osvQueries) {
      const sep = key.lastIndexOf("::");
      const pkg = key.slice(0, sep);
      const eco = key.slice(sep + 2);
      try {
        const vulns = await fetchOsvForPackage(pkg, eco);
        counts.osv.fetched += vulns.length;
        for (const v of vulns) {
          for (const slug of slugs) {
            const cfg = configs.find(c => c.slug === slug)!;
            const t = normaliseOsvVuln(v, slug, cfg, kevMap);
            if (t) rawThreats.push(t);
            else   counts.osv.skipped++;
          }
        }
      } catch (e) {
        counts.osv.errors++;
        console.error(`OSV error for ${pkg}:`, e);
      }
      await sleep(300);
    }

    // ── Phase 3: GHSA — deduplicated by ecosystem ─────────────────────
    console.log("Phase 3 [ghsa]: fetching per unique ecosystem...");
    const ecosystemToSlugs = new Map<string, string[]>();
    for (const config of configs) {
      const slugs = ecosystemToSlugs.get(config.ghsaEcosystem) ?? [];
      slugs.push(config.slug);
      ecosystemToSlugs.set(config.ghsaEcosystem, slugs);
    }

    for (const [ecosystem, slugs] of ecosystemToSlugs) {
      console.log(`  → GHSA ecosystem: ${ecosystem} (${slugs.join(", ")})`);
      try {
        const advisories = await fetchGhsaForEcosystem(
          ecosystem,
          process.env.GITHUB_TOKEN
        );
        counts.ghsa.fetched += advisories.length;
        for (const adv of advisories) {
          for (const slug of slugs) {
            const cfg = configs.find(c => c.slug === slug)!;
            const t = normaliseGhsa(adv, slug, cfg, kevMap);
            if (t) rawThreats.push(t);
            else   counts.ghsa.skipped++;
          }
        }
      } catch (e) {
        counts.ghsa.errors++;
        console.error(`GHSA error for ${ecosystem}:`, e);
      }
    }

    // ── Phase 5: Deduplicate (runs BEFORE Phase 4 to reduce NVD calls) ─
    console.log(`Phase 5: deduplicating ${rawThreats.length} raw records...`);
    const deduped = deduplicateThreats(rawThreats);
    console.log(`  → ${deduped.length} unique threats after dedup`);

    // ── Drop below-threshold records ──────────────────────────────────
    const toInsert = deduped.filter(
      t => t.severity !== "low" && t.severity !== "info"
    );
    console.log(`  → ${toInsert.length} threats at HIGH+ severity`);

    if (DRY_RUN) {
      console.log(`[DRY RUN] Would upsert ${toInsert.length} threats`);
      console.log(JSON.stringify(toInsert.slice(0, 5), null, 2));
      await closeSyncLog(logId, counts);
      return;
    }

    // ── Phase 4: NVD enrichment (selective, post-dedup, skipped in DRY_RUN) ─
    console.log("Phase 4: NVD enrichment pass...");
    const nvdDelay = process.env.NVD_API_KEY ? 650 : 6500;
    for (const t of toInsert) {
      if (!t.cveId) continue;
      if (t.severity !== "info" && t.owaspRefs.length > 0) continue;
      try {
        const enrichment = await enrichFromNvd(t.cveId, process.env.NVD_API_KEY);
        if (enrichment) {
          if (enrichment.cvssScore !== null) {
            t.severity = normaliseSeverity("nvd", undefined, enrichment.cvssScore);
          }
          if (enrichment.cweIds.length > 0) {
            t.owaspRefs = mapCwesToOwasp(enrichment.cweIds);
          }
          counts.nvd.fetched++;
          counts.nvd.upserted++;
        }
        // Only rate-limit when a request was actually made
        await sleep(nvdDelay);
      } catch {
        counts.nvd.errors++;
      }
    }

    // ── Phase 6: Upsert threat rows ───────────────────────────────────
    console.log("Phase 6: upserting threat rows...");
    const updatedIds: string[] = [];
    for (const t of toInsert) {
      try {
        await upsertThreat(t);
        updatedIds.push(t.publicId);
        counts[sourceKey(t.source)].upserted++;
      } catch (e) {
        console.error(`Failed upserting ${t.publicId}:`, e);
      }
    }

    // ── Phase 7: Upsert threat_stack rows ─────────────────────────────
    console.log("Phase 7: upserting threat_stack rows...");
    for (const t of toInsert) {
      for (const slug of t.affectedStackSlugs) {
        await upsertThreatStack(t.publicId, slug, t.severity, stackIdMap);
      }
    }

    // ── Phase 8: Refresh isMitigatedByRules ───────────────────────────
    console.log("Phase 8: refreshing mitigation flags...");
    await refreshMitigationFlags(updatedIds);

    // ── Phase 9: Close syncLog ────────────────────────────────────────
    await closeSyncLog(logId, counts);
    console.log("✓ Sync complete.");
    console.log(JSON.stringify(counts, null, 2));

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await closeSyncLog(logId, counts, msg).catch(() => {});
    console.error("Sync failed:", msg);
    process.exitCode = 1;
  }
}

main()
  .catch(err => {
    console.error("Fatal:", err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
