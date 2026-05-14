import { config } from "dotenv";
import { defineConfig } from "drizzle-kit";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, ".env") });

export default defineConfig({
  schema: resolve(__dirname, "../packages/db/src/schema.ts"),
  out: resolve(__dirname, "./drizzle"),
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? "",
    ssl: true,
  },
});
