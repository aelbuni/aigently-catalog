import { STACK_REGISTRY } from "./stack-registry.js";

export const LAUNCH_STACK_SLUGS = STACK_REGISTRY
  .filter(s => s.catalogStatus === "launch")
  .sort((a, b) => a.sortOrder - b.sortOrder)
  .map(s => s.slug);

export const COMING_SOON_STACK_SLUGS = STACK_REGISTRY
  .filter(s => s.catalogStatus === "coming_soon")
  .sort((a, b) => a.sortOrder - b.sortOrder)
  .map(s => s.slug);

export const ALL_CATALOG_STACK_SLUGS = [...LAUNCH_STACK_SLUGS, ...COMING_SOON_STACK_SLUGS];

export function isLaunchStackSlug(s: string): boolean {
  return LAUNCH_STACK_SLUGS.includes(s);
}

export function isComingSoonStackSlug(s: string): boolean {
  return COMING_SOON_STACK_SLUGS.includes(s);
}

export const REAL_GHSA_PUBLIC_IDS = new Set<string>([
  // e.g. "GHSA-7gfc-8cq8-jh5f" — populate when advisory IDs are verified
]);
