import type { DirectiveAtom } from "./atoms.js";

const SEV_RANK: Record<DirectiveAtom["severity"], number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

/** Within a layer, detect atoms with near-identical intent but contradictory direction. */
export function resolveConflicts(atoms: DirectiveAtom[]): {
  resolved: DirectiveAtom[];
  conflictCount: number;
} {
  const groups = new Map<string, DirectiveAtom[]>();

  for (const atom of atoms) {
    const key = normalizeKey(atom.content);
    const group = groups.get(key) ?? [];
    group.push(atom);
    groups.set(key, group);
  }

  const resolved: DirectiveAtom[] = [];
  let conflictCount = 0;

  for (const group of groups.values()) {
    if (group.length === 1) {
      resolved.push(group[0]!);
      continue;
    }
    conflictCount += group.length - 1;
    const winner = group.reduce((a, b) =>
      SEV_RANK[a.severity] >= SEV_RANK[b.severity] ? a : b
    );
    resolved.push({ ...winner, conflictResolution: "conflict_resolved" });
  }

  return { resolved, conflictCount };
}

function normalizeKey(content: string): string {
  return content
    .toLowerCase()
    .replace(/\b(do not|never|avoid|always|ensure|require)\b/gi, "")
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
}
