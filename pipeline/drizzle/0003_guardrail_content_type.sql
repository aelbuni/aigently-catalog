-- Migration: replace layer_id FK with content_type on summarized_guardrail
-- All existing rows are stale (only 6 auth_session entries), safe to delete.

DELETE FROM summarized_guardrail;

ALTER TABLE summarized_guardrail
  ADD COLUMN content_type text NOT NULL DEFAULT 'patterns';

ALTER TABLE summarized_guardrail
  DROP CONSTRAINT IF EXISTS summarized_guardrail_layer_id_fkey;

ALTER TABLE summarized_guardrail
  DROP COLUMN IF EXISTS layer_id;

ALTER TABLE summarized_guardrail
  ADD CONSTRAINT summarized_guardrail_stack_content_key UNIQUE (stack_id, content_type);

ALTER TABLE summarized_guardrail
  DROP COLUMN IF EXISTS ide_slug;
