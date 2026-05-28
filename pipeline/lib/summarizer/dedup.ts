import type { DirectiveAtom } from "./atoms.js";

/** Remove semantically identical atoms — keep the one with more detail (longer + more CWEs). */
export function deduplicateAtoms(atoms: DirectiveAtom[]): DirectiveAtom[] {
  const seen = new Set<string>();
  const result: DirectiveAtom[] = [];
  for (const atom of atoms) {
    const fingerprint = atom.content
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "")
      .slice(0, 60);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    result.push({ ...atom, conflictResolution: "deduplicated" });
  }
  return result;
}
