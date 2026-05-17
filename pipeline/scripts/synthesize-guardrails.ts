import "../lib/load-env.js";

import { pool } from "../lib/db/index.js";
import { bulkRunSummarizer } from "../lib/summarizer/pipeline.js";

const MODE = (process.env.SYNTHESIZE_MODE ?? "empty") as "empty" | "stale" | "all";

async function main() {
  console.log(`Synthesizing guardrails (mode: ${MODE})...`);

  const { generated, skipped, errors } = await bulkRunSummarizer(MODE);

  if (errors.length > 0) {
    console.error(`\nErrors (${errors.length}):`);
    for (const e of errors) console.error(`  - ${e}`);
  }

  console.log(`\nDone: ${generated} guardrails generated, ${skipped} skipped.`);
  if (errors.length > 0) process.exitCode = 1;
}

main()
  .catch((err) => {
    console.error("Synthesis failed:", err);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
