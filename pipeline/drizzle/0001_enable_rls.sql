-- Enable Row-Level Security on all tables.
-- No policies are defined, so unauthenticated (anon) callers get zero rows.
-- The postgres superuser role used by the pipeline bypasses RLS and is unaffected.

ALTER TABLE "account"                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE "article"                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE "article_feedback"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "article_rule_map"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "authenticator"           ENABLE ROW LEVEL SECURITY;
ALTER TABLE "content_revision"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ide"                     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "layer"                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "policy_template"         ENABLE ROW LEVEL SECURITY;
ALTER TABLE "policy_template_stack"   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule"                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_ide"                ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_layer_map"          ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_review"             ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_review_helpful"     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_severity_tag"       ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_stack"              ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_threat_map"         ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_usage_daily"        ENABLE ROW LEVEL SECURITY;
ALTER TABLE "session"                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE "stack"                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE "stack_coverage_area"     ENABLE ROW LEVEL SECURITY;
ALTER TABLE "stack_framework_feature" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "summarized_guardrail"    ENABLE ROW LEVEL SECURITY;
ALTER TABLE "sync_log"                ENABLE ROW LEVEL SECURITY;
ALTER TABLE "threat"                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE "threat_layer"            ENABLE ROW LEVEL SECURITY;
ALTER TABLE "threat_stack"            ENABLE ROW LEVEL SECURITY;
ALTER TABLE "user"                    ENABLE ROW LEVEL SECURITY;
ALTER TABLE "verificationToken"       ENABLE ROW LEVEL SECURITY;
