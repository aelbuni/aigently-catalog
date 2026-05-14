import { sql, eq } from "drizzle-orm";
import { db, pool, threat, threatStack, syncLog } from "../../lib/db";
import type { NormalisedThreat, SyncSummary } from "./types";

export async function upsertThreat(t: NormalisedThreat): Promise<void> {
  const now = new Date();
  const row = {
    publicId:            t.publicId,
    family:              t.family,
    name:                t.name.slice(0, 255),
    severity:            t.severity,
    description:         t.description,
    cveId:               t.cveId,
    externalId:          t.externalId,
    source:              t.source,
    sourceUrl:           t.sourceUrl,
    publishedAt:         t.publishedAt,
    syncedAt:            now,
    owaspRefs:           t.owaspRefs,
    mitreAttackIds:      t.mitreAttackIds,
    affectedProducts:    t.affectedProducts,
    patchedVersion:      t.patchedVersion,
    isActivelyExploited: t.isActivelyExploited,
    cisaActionDue:       t.cisaActionDue,
    details:             t.details,
    updatedAt:           now,
    // aiAmplification intentionally absent — editorial-only field
  };

  await db
    .insert(threat)
    .values(row)
    .onConflictDoUpdate({
      // Conflict on publicId (PK) — always the CVE ID when present, so it
      // correctly matches both seeded curated rows and pipeline-ingested rows
      // for the same threat regardless of which externalId each source uses.
      target: threat.publicId,
      set: {
        severity:            row.severity,
        syncedAt:            row.syncedAt,
        isActivelyExploited: row.isActivelyExploited,
        cisaActionDue:       row.cisaActionDue,
        owaspRefs:           row.owaspRefs,
        patchedVersion:      row.patchedVersion,
        updatedAt:           row.updatedAt,
        // Preserve existing curator-edited content; only fill if currently null
        description: sql`COALESCE(threat.description, EXCLUDED.description)`,
        sourceUrl:   sql`COALESCE(threat.source_url,   EXCLUDED.source_url)`,
        publishedAt: sql`COALESCE(threat.published_at, EXCLUDED.published_at)`,
        // Update externalId when the seeded row used the CVE ID as a placeholder
        externalId:  sql`COALESCE(threat.external_id, EXCLUDED.external_id)`,
      },
    });
}

export async function upsertThreatStack(
  threatPublicId: string,
  stackSlug:      string,
  severity:       "critical" | "high" | "medium" | "low" | "info",
  stackIdMap:     Map<string, number>
): Promise<void> {
  const stackId = stackIdMap.get(stackSlug);
  if (!stackId) return;

  await db
    .insert(threatStack)
    .values({
      threatId:           threatPublicId,
      stackId:            stackId,
      severity:           severity,
      isMitigatedByRules: false,
    })
    .onConflictDoUpdate({
      target: [threatStack.threatId, threatStack.stackId],
      set: {
        severity: sql`EXCLUDED.severity`,
        // isMitigatedByRules is NOT updated here — refreshMitigationFlags handles it
      },
    });
}

export async function refreshMitigationFlags(
  updatedPublicIds: string[]
): Promise<void> {
  if (updatedPublicIds.length === 0) return;

  // Drizzle always expands JS arrays into individual params ($1,$2,...) which
  // breaks ANY(). Use the underlying pg pool directly — it natively binds a
  // JS string[] as a single postgres array parameter.
  await pool.query(
    `UPDATE threat_stack ts
     SET is_mitigated_by_rules = EXISTS (
       SELECT 1 FROM rule_threat_map rtm WHERE rtm.threat_id = ts.threat_id
     )
     WHERE ts.threat_id = ANY($1)`,
    [updatedPublicIds]
  );
}

export async function openSyncLog(): Promise<number> {
  const [row] = await db
    .insert(syncLog)
    .values({ status: "running", sourceSummary: {} })
    .returning({ id: syncLog.id });
  return row.id;
}

export async function closeSyncLog(
  logId:   number,
  summary: SyncSummary,
  error?:  string
): Promise<void> {
  const totalResult = await db.execute<{ total: string }>(
    sql`SELECT COUNT(*)::text AS total FROM threat`
  );
  const total = totalResult.rows[0]?.total ?? "0";

  const coveredResult = await db.execute<{ covered: string }>(sql`
    SELECT COUNT(DISTINCT threat_id)::text AS covered FROM rule_threat_map
  `);
  const covered = coveredResult.rows[0]?.covered ?? "0";

  const pct = total === "0"
    ? 0
    : Math.round((Number(covered) / Number(total)) * 100);

  await db
    .update(syncLog)
    .set({
      finishedAt:      new Date(),
      sourceSummary:   summary,
      coveragePercent: pct,
      status:          error ? "failed" : "success",
      errorMessage:    error ?? null,
    })
    .where(eq(syncLog.id, logId));
}
