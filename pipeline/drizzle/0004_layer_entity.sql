--> statement-breakpoint
CREATE TABLE "layer" (
  "id"   uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "slug" text UNIQUE NOT NULL,
  "name" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threat_layer" (
  "id"        uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "threat_id" text NOT NULL REFERENCES "threat"("public_id") ON DELETE CASCADE,
  "layer_id"  uuid NOT NULL REFERENCES "layer"("id") ON DELETE CASCADE,
  "relevance" text NOT NULL DEFAULT 'primary'
              CHECK ("relevance" IN ('primary','secondary')),
  "rationale" text,
  "added_at"  timestamp with time zone NOT NULL DEFAULT now()
);
--> statement-breakpoint
CREATE UNIQUE INDEX "uq_threat_layer" ON "threat_layer" ("threat_id", "layer_id");
--> statement-breakpoint
ALTER TABLE "rule"
  ADD COLUMN "rule_type"      text NOT NULL DEFAULT 'pattern',
  ADD COLUMN "strength_score" integer NOT NULL DEFAULT 0;
--> statement-breakpoint
INSERT INTO "layer" ("id", "slug", "name")
SELECT gen_random_uuid(), v.slug, v.name
FROM (VALUES
  ('auth_session',        'Authentication & Session'),
  ('authz_access',        'Authorization & Access Control'),
  ('input_validation',    'Input Validation & Sanitization'),
  ('secrets_credentials', 'Secrets & Credentials'),
  ('dependency_supply',   'Dependency & Supply Chain'),
  ('data_privacy',        'Data Privacy & Compliance'),
  ('api_security',        'API Security & Rate Limiting'),
  ('database',            'Database Hardening'),
  ('infrastructure',      'Infrastructure & Deployment'),
  ('caching_cdn',         'Caching & CDN'),
  ('frontend_network',    'Frontend & Network Security'),
  ('observability',       'Observability & Incident Response'),
  ('resilience',          'Resilience & Recovery'),
  ('ai_safety',           'AI & LLM Safety'),
  ('code_quality',        'Code Quality & Patterns')
) AS v(slug, name)
WHERE NOT EXISTS (SELECT 1 FROM "layer" WHERE "slug" = v.slug);
--> statement-breakpoint
ALTER TABLE "rule_layer_map" ADD COLUMN "layer_id" uuid REFERENCES "layer"("id") ON DELETE CASCADE;
--> statement-breakpoint
UPDATE "rule_layer_map"
  SET "layer_id" = (SELECT "id" FROM "layer" WHERE "slug" = 'auth_session')
  WHERE "layer" = 'security';
--> statement-breakpoint
UPDATE "rule_layer_map"
  SET "layer_id" = (SELECT "id" FROM "layer" WHERE "slug" = 'code_quality')
  WHERE "layer" IN ('architecture', 'code_quality');
--> statement-breakpoint
UPDATE "rule_layer_map"
  SET "layer_id" = (SELECT "id" FROM "layer" WHERE "slug" = 'auth_session')
  WHERE "layer_id" IS NULL;
--> statement-breakpoint
ALTER TABLE "rule_layer_map" ALTER COLUMN "layer_id" SET NOT NULL;
--> statement-breakpoint
ALTER TABLE "rule_layer_map" DROP CONSTRAINT IF EXISTS "rule_layer_map_rule_id_layer_pk";
--> statement-breakpoint
ALTER TABLE "rule_layer_map" DROP CONSTRAINT IF EXISTS "rule_layer_map_pkey";
--> statement-breakpoint
ALTER TABLE "rule_layer_map"
  ADD CONSTRAINT "rule_layer_map_rule_id_layer_id_pk"
  PRIMARY KEY ("rule_id", "layer_id");
--> statement-breakpoint
ALTER TABLE "rule_layer_map" DROP COLUMN IF EXISTS "layer";
