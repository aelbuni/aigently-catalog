import { createHash } from "crypto";

export function buildCacheKey(
  stackSlug: string,
  layerSlug: string,
  ruleType: string,
  ruleContents: string[]
): string {
  const contentHash = ruleContents
    .map((c) => createHash("sha256").update(c).digest("hex").slice(0, 8))
    .sort()
    .join("|");
  return `summarize:${stackSlug}:${layerSlug}:${ruleType}:${contentHash}`;
}

export function buildBatchCacheKeys(
  stackSlug: string,
  ruleType: string,
  layerRuleContents: Record<string, string[]>
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [layerSlug, contents] of Object.entries(layerRuleContents)) {
    result[layerSlug] = buildCacheKey(stackSlug, layerSlug, ruleType, contents);
  }
  return result;
}
