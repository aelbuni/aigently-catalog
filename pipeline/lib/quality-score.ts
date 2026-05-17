/** Compute a 0–10 quality score for a synthesized guardrail. Identical to aigently-v1 computeQualityScore. */
export function computeQualityScore(row: {
  conflictCount: number;
  sourceRuleCount: number;
  contentLength: number;
  generatedAt: Date;
}): number {
  const conflictScore     = Math.max(0, 10 - row.conflictCount * 1.5);
  const breadthScore      = Math.min(10, (row.sourceRuleCount ?? 0) * 2);
  const completenessScore = Math.min(10, (row.contentLength ?? 0) / 200);
  const daysSince         = (Date.now() - row.generatedAt.getTime()) / 86_400_000;
  const freshnessScore    = Math.max(0, 10 - daysSince * 0.3);
  return Math.round((conflictScore + breadthScore + completenessScore + freshnessScore) / 4);
}
