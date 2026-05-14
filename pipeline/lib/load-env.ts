import path from "node:path";
import { fileURLToPath } from "node:url";

import { config } from "dotenv";

/** Load `pipeline/.env` — copy pipeline/.env.example to pipeline/.env and fill in your keys. */
const webRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
config({ path: path.join(webRoot, ".env") });
