CREATE TYPE "public"."framework_feature_status" AS ENUM('built_in', 'manual_cfg', 'not_supported');--> statement-breakpoint
CREATE TYPE "public"."rule_layer" AS ENUM('security', 'architecture', 'code_quality');--> statement-breakpoint
CREATE TYPE "public"."severity_level" AS ENUM('critical', 'high', 'medium', 'low', 'info');--> statement-breakpoint
CREATE TYPE "public"."stack_catalog_status" AS ENUM('launch', 'coming_soon');--> statement-breakpoint
CREATE TYPE "public"."threat_family" AS ENUM('owasp_web', 'owasp_llm', 'mitre_atlas', 'vibe_coding');--> statement-breakpoint
CREATE TYPE "public"."threat_source" AS ENUM('nvd', 'osv', 'ghsa', 'cisa_kev', 'aigently', 'mitre_atlas', 'aigently_internal');--> statement-breakpoint
CREATE TABLE "account" (
	"userId" text NOT NULL,
	"type" text NOT NULL,
	"provider" text NOT NULL,
	"providerAccountId" text NOT NULL,
	"refresh_token" text,
	"access_token" text,
	"expires_at" integer,
	"token_type" text,
	"scope" text,
	"id_token" text,
	"session_state" text,
	CONSTRAINT "account_provider_providerAccountId_pk" PRIMARY KEY("provider","providerAccountId")
);
--> statement-breakpoint
CREATE TABLE "article" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"title" text NOT NULL,
	"excerpt" text,
	"reading_minutes" smallint,
	"published_at" timestamp with time zone,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"content_path" text,
	"body_mdx" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "article_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "article_feedback" (
	"article_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"helpful" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "article_feedback_article_id_user_id_pk" PRIMARY KEY("article_id","user_id")
);
--> statement-breakpoint
CREATE TABLE "article_rule_map" (
	"article_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	CONSTRAINT "article_rule_map_article_id_rule_id_pk" PRIMARY KEY("article_id","rule_id")
);
--> statement-breakpoint
CREATE TABLE "authenticator" (
	"credentialID" text NOT NULL,
	"userId" text NOT NULL,
	"providerAccountId" text NOT NULL,
	"credentialPublicKey" text NOT NULL,
	"counter" integer NOT NULL,
	"credentialDeviceType" text NOT NULL,
	"credentialBackedUp" boolean NOT NULL,
	"transports" text,
	CONSTRAINT "authenticator_userId_credentialID_pk" PRIMARY KEY("userId","credentialID"),
	CONSTRAINT "authenticator_credentialID_unique" UNIQUE("credentialID")
);
--> statement-breakpoint
CREATE TABLE "content_revision" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "content_revision_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"entity_type" text NOT NULL,
	"entity_id" uuid NOT NULL,
	"git_sha" text NOT NULL,
	"synced_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ide" (
	"id" smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "ide_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 32767 START WITH 1 CACHE 1),
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"sort_order" smallint DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ide_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "layer" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"concern_statement" text DEFAULT '' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"sort_order" integer DEFAULT 100 NOT NULL,
	CONSTRAINT "layer_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "policy_template" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "policy_template_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"layer" "rule_layer" NOT NULL,
	"body_markdown" text,
	"sort_order" smallint DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "policy_template_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "policy_template_stack" (
	"template_id" integer NOT NULL,
	"stack_id" smallint NOT NULL,
	CONSTRAINT "policy_template_stack_template_id_stack_id_pk" PRIMARY KEY("template_id","stack_id")
);
--> statement-breakpoint
CREATE TABLE "rule" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"version" text NOT NULL,
	"date_added" date NOT NULL,
	"last_updated" date NOT NULL,
	"author" text NOT NULL,
	"certified" boolean DEFAULT false NOT NULL,
	"complexity" text,
	"line_count" integer,
	"rule_type" text,
	"strength_score" integer DEFAULT 0 NOT NULL,
	"content_path" text,
	"body_mdx" text,
	"summary_mdx" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "rule_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "rule_ide" (
	"rule_id" uuid NOT NULL,
	"ide_id" smallint NOT NULL,
	CONSTRAINT "rule_ide_rule_id_ide_id_pk" PRIMARY KEY("rule_id","ide_id")
);
--> statement-breakpoint
CREATE TABLE "rule_layer_map" (
	"rule_id" uuid NOT NULL,
	"layer_id" uuid NOT NULL,
	CONSTRAINT "rule_layer_map_rule_id_layer_id_pk" PRIMARY KEY("rule_id","layer_id")
);
--> statement-breakpoint
CREATE TABLE "rule_review" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"rule_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"rating" smallint NOT NULL,
	"review_text" text NOT NULL,
	"ide_used" text NOT NULL,
	"stack_tested" text NOT NULL,
	"helpful_count" integer DEFAULT 0 NOT NULL,
	"author_handle" text,
	"is_verified" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rule_review_helpful" (
	"review_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "rule_review_helpful_review_id_user_id_pk" PRIMARY KEY("review_id","user_id")
);
--> statement-breakpoint
CREATE TABLE "rule_severity_tag" (
	"rule_id" uuid NOT NULL,
	"severity" "severity_level" NOT NULL,
	CONSTRAINT "rule_severity_tag_rule_id_severity_pk" PRIMARY KEY("rule_id","severity")
);
--> statement-breakpoint
CREATE TABLE "rule_stack" (
	"rule_id" uuid NOT NULL,
	"stack_id" smallint NOT NULL,
	CONSTRAINT "rule_stack_rule_id_stack_id_pk" PRIMARY KEY("rule_id","stack_id")
);
--> statement-breakpoint
CREATE TABLE "rule_threat_map" (
	"rule_id" uuid NOT NULL,
	"threat_id" text NOT NULL,
	CONSTRAINT "rule_threat_map_rule_id_threat_id_pk" PRIMARY KEY("rule_id","threat_id")
);
--> statement-breakpoint
CREATE TABLE "rule_usage_daily" (
	"rule_id" uuid NOT NULL,
	"bucket_date" date NOT NULL,
	"copy_count" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "rule_usage_daily_rule_id_bucket_date_pk" PRIMARY KEY("rule_id","bucket_date")
);
--> statement-breakpoint
CREATE TABLE "session" (
	"sessionToken" text PRIMARY KEY NOT NULL,
	"userId" text NOT NULL,
	"expires" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "stack" (
	"id" smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "stack_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 32767 START WITH 1 CACHE 1),
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"logo_path" text,
	"sort_order" smallint DEFAULT 0 NOT NULL,
	"catalog_status" "stack_catalog_status" DEFAULT 'launch' NOT NULL,
	"security_grade" text,
	"grade_rationale" text,
	"ecosystem" text,
	"nvd_keywords" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"osv_ecosystem" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "stack_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "stack_coverage_area" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "stack_coverage_area_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"stack_id" smallint NOT NULL,
	"area_name" text NOT NULL,
	"coverage_percent" smallint,
	"notes" text
);
--> statement-breakpoint
CREATE TABLE "stack_framework_feature" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "stack_framework_feature_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"stack_id" smallint NOT NULL,
	"feature_name" text NOT NULL,
	"status" "framework_feature_status" NOT NULL,
	"notes" text
);
--> statement-breakpoint
CREATE TABLE "summarized_guardrail" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"stack_id" smallint NOT NULL,
	"layer_id" uuid NOT NULL,
	"ide_slug" text DEFAULT 'all' NOT NULL,
	"content" text NOT NULL,
	"source_rule_ids" uuid[] NOT NULL,
	"provenance" jsonb,
	"conflict_count" integer DEFAULT 0 NOT NULL,
	"cache_key" text NOT NULL,
	"summarizer_version" text NOT NULL,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"quality_score" smallint DEFAULT 0 NOT NULL,
	"score_override" smallint,
	"score_note" text,
	CONSTRAINT "summarized_guardrail_cache_key_unique" UNIQUE("cache_key")
);
--> statement-breakpoint
CREATE TABLE "sync_log" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "sync_log_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	"source_summary" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"coverage_percent" smallint,
	"status" text DEFAULT 'running' NOT NULL,
	"error_message" text
);
--> statement-breakpoint
CREATE TABLE "threat" (
	"public_id" text PRIMARY KEY NOT NULL,
	"family" "threat_family" NOT NULL,
	"name" text NOT NULL,
	"severity" "severity_level",
	"description" text,
	"ai_amplification" text,
	"cve_id" text,
	"external_id" text,
	"source" "threat_source" DEFAULT 'aigently' NOT NULL,
	"source_url" text,
	"published_at" timestamp with time zone,
	"synced_at" timestamp with time zone,
	"mitre_attack_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"owasp_refs" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"affected_products" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"patched_version" text,
	"is_actively_exploited" boolean DEFAULT false NOT NULL,
	"cisa_action_due" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "threat_external_id_unique" UNIQUE("external_id")
);
--> statement-breakpoint
CREATE TABLE "threat_layer" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"threat_id" text NOT NULL,
	"layer_id" uuid NOT NULL,
	"relevance" text DEFAULT 'primary' NOT NULL,
	"rationale" text,
	"added_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threat_stack" (
	"threat_id" text NOT NULL,
	"stack_id" smallint NOT NULL,
	"severity" "severity_level" NOT NULL,
	"is_mitigated_by_rules" boolean DEFAULT false NOT NULL,
	CONSTRAINT "threat_stack_threat_id_stack_id_pk" PRIMARY KEY("threat_id","stack_id")
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text,
	"email" text,
	"emailVerified" timestamp,
	"image" text,
	CONSTRAINT "user_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "verificationToken" (
	"identifier" text NOT NULL,
	"token" text NOT NULL,
	"expires" timestamp NOT NULL,
	CONSTRAINT "verificationToken_identifier_token_pk" PRIMARY KEY("identifier","token")
);
--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_userId_user_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "article_feedback" ADD CONSTRAINT "article_feedback_article_id_article_id_fk" FOREIGN KEY ("article_id") REFERENCES "public"."article"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "article_feedback" ADD CONSTRAINT "article_feedback_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "article_rule_map" ADD CONSTRAINT "article_rule_map_article_id_article_id_fk" FOREIGN KEY ("article_id") REFERENCES "public"."article"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "article_rule_map" ADD CONSTRAINT "article_rule_map_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authenticator" ADD CONSTRAINT "authenticator_userId_user_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_template_stack" ADD CONSTRAINT "policy_template_stack_template_id_policy_template_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."policy_template"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_template_stack" ADD CONSTRAINT "policy_template_stack_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_ide" ADD CONSTRAINT "rule_ide_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_ide" ADD CONSTRAINT "rule_ide_ide_id_ide_id_fk" FOREIGN KEY ("ide_id") REFERENCES "public"."ide"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_layer_map" ADD CONSTRAINT "rule_layer_map_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_layer_map" ADD CONSTRAINT "rule_layer_map_layer_id_layer_id_fk" FOREIGN KEY ("layer_id") REFERENCES "public"."layer"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_review" ADD CONSTRAINT "rule_review_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_review" ADD CONSTRAINT "rule_review_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_review_helpful" ADD CONSTRAINT "rule_review_helpful_review_id_rule_review_id_fk" FOREIGN KEY ("review_id") REFERENCES "public"."rule_review"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_review_helpful" ADD CONSTRAINT "rule_review_helpful_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_severity_tag" ADD CONSTRAINT "rule_severity_tag_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_stack" ADD CONSTRAINT "rule_stack_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_stack" ADD CONSTRAINT "rule_stack_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_threat_map" ADD CONSTRAINT "rule_threat_map_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_threat_map" ADD CONSTRAINT "rule_threat_map_threat_id_threat_public_id_fk" FOREIGN KEY ("threat_id") REFERENCES "public"."threat"("public_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_usage_daily" ADD CONSTRAINT "rule_usage_daily_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_userId_user_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_coverage_area" ADD CONSTRAINT "stack_coverage_area_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_framework_feature" ADD CONSTRAINT "stack_framework_feature_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "summarized_guardrail" ADD CONSTRAINT "summarized_guardrail_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "summarized_guardrail" ADD CONSTRAINT "summarized_guardrail_layer_id_layer_id_fk" FOREIGN KEY ("layer_id") REFERENCES "public"."layer"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_layer" ADD CONSTRAINT "threat_layer_threat_id_threat_public_id_fk" FOREIGN KEY ("threat_id") REFERENCES "public"."threat"("public_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_layer" ADD CONSTRAINT "threat_layer_layer_id_layer_id_fk" FOREIGN KEY ("layer_id") REFERENCES "public"."layer"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_stack" ADD CONSTRAINT "threat_stack_threat_id_threat_public_id_fk" FOREIGN KEY ("threat_id") REFERENCES "public"."threat"("public_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_stack" ADD CONSTRAINT "threat_stack_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "content_revision_entity_sha" ON "content_revision" USING btree ("entity_type","entity_id","git_sha");--> statement-breakpoint
CREATE UNIQUE INDEX "stack_coverage_area_stack_area" ON "stack_coverage_area" USING btree ("stack_id","area_name");--> statement-breakpoint
CREATE UNIQUE INDEX "stack_framework_feature_stack_feature" ON "stack_framework_feature" USING btree ("stack_id","feature_name");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_threat_layer" ON "threat_layer" USING btree ("threat_id","layer_id");