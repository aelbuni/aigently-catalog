CREATE TYPE "public"."framework_feature_status" AS ENUM('built_in', 'manual_cfg', 'not_supported');--> statement-breakpoint
CREATE TYPE "public"."threat_source" AS ENUM('nvd', 'osv', 'ghsa', 'cisa_kev', 'aigently', 'mitre_atlas', 'aigently_internal');--> statement-breakpoint
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
CREATE TABLE "threat_stack" (
	"threat_id" text NOT NULL,
	"stack_id" smallint NOT NULL,
	"severity" "severity_level" NOT NULL,
	"is_mitigated_by_rules" boolean DEFAULT false NOT NULL,
	CONSTRAINT "threat_stack_threat_id_stack_id_pk" PRIMARY KEY("threat_id","stack_id")
);
--> statement-breakpoint
ALTER TABLE "rule_review" ADD COLUMN "author_handle" text;--> statement-breakpoint
ALTER TABLE "rule_review" ADD COLUMN "is_verified" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "stack" ADD COLUMN "security_grade" text;--> statement-breakpoint
ALTER TABLE "stack" ADD COLUMN "grade_rationale" text;--> statement-breakpoint
ALTER TABLE "stack" ADD COLUMN "ecosystem" text;--> statement-breakpoint
ALTER TABLE "stack" ADD COLUMN "nvd_keywords" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "stack" ADD COLUMN "osv_ecosystem" text;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "cve_id" text;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "external_id" text;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "source" "threat_source" DEFAULT 'aigently' NOT NULL;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "source_url" text;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "published_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "synced_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "mitre_attack_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "owasp_refs" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "affected_products" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "patched_version" text;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "is_actively_exploited" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "threat" ADD COLUMN "cisa_action_due" text;--> statement-breakpoint
ALTER TABLE "policy_template_stack" ADD CONSTRAINT "policy_template_stack_template_id_policy_template_id_fk" FOREIGN KEY ("template_id") REFERENCES "public"."policy_template"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_template_stack" ADD CONSTRAINT "policy_template_stack_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_coverage_area" ADD CONSTRAINT "stack_coverage_area_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_framework_feature" ADD CONSTRAINT "stack_framework_feature_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_stack" ADD CONSTRAINT "threat_stack_threat_id_threat_public_id_fk" FOREIGN KEY ("threat_id") REFERENCES "public"."threat"("public_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_stack" ADD CONSTRAINT "threat_stack_stack_id_stack_id_fk" FOREIGN KEY ("stack_id") REFERENCES "public"."stack"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "stack_coverage_area_stack_area" ON "stack_coverage_area" USING btree ("stack_id","area_name");--> statement-breakpoint
CREATE UNIQUE INDEX "stack_framework_feature_stack_feature" ON "stack_framework_feature" USING btree ("stack_id","feature_name");--> statement-breakpoint
UPDATE "threat" SET "external_id" = "public_id" WHERE "external_id" IS NULL;--> statement-breakpoint
ALTER TABLE "threat" ADD CONSTRAINT "threat_external_id_unique" UNIQUE("external_id");--> statement-breakpoint
CREATE MATERIALIZED VIEW "rule_weekly_usage" AS (
  SELECT
    "rule_id",
    (date_trunc('week', "bucket_date"::timestamp with time zone AT TIME ZONE 'UTC'))::date AS bucket_week_start,
    SUM("copy_count")::integer AS total_copies
  FROM "rule_usage_daily"
  GROUP BY "rule_id", (date_trunc('week', "bucket_date"::timestamp with time zone AT TIME ZONE 'UTC'))::date
);--> statement-breakpoint
CREATE UNIQUE INDEX "rule_weekly_usage_rule_week_uniq" ON "rule_weekly_usage" USING btree ("rule_id", "bucket_week_start");