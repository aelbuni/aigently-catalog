import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "dotenv";

/** Load `pipeline/.env` — copy pipeline/.env.example to pipeline/.env and fill in your keys. */
const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.join(__dirname, "..", ".env") });
