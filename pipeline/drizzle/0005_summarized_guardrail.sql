--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "summarized_guardrail" (
  "id"                 uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "stack_id"           smallint NOT NULL REFERENCES "stack"("id"),
  "layer_id"           uuid NOT NULL REFERENCES "layer"("id"),
  "ide_slug"           text NOT NULL DEFAULT 'all',
  "content"            text NOT NULL,
  "source_rule_ids"    uuid[] NOT NULL,
  "provenance"         jsonb,
  "conflict_count"     integer NOT NULL DEFAULT 0,
  "cache_key"          text NOT NULL,
  "summarizer_version" text NOT NULL,
  "generated_at"       timestamp with time zone NOT NULL DEFAULT now(),
  "expires_at"         timestamp with time zone,
  "quality_score"      smallint NOT NULL DEFAULT 0,
  "score_override"     smallint,
  "score_note"         text,
  CONSTRAINT "summarized_guardrail_cache_key_unique" UNIQUE("cache_key")
);
