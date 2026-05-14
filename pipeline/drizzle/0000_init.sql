CREATE TYPE "public"."rule_layer" AS ENUM('security', 'architecture', 'code_quality');--> statement-breakpoint
CREATE TYPE "public"."severity_level" AS ENUM('critical', 'high', 'medium', 'low', 'info');--> statement-breakpoint
CREATE TYPE "public"."threat_family" AS ENUM('owasp_web', 'owasp_llm', 'mitre_atlas', 'vibe_coding');--> statement-breakpoint
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
	"content_path" text,
	"body_mdx" text,
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
	"layer" "rule_layer" NOT NULL,
	CONSTRAINT "rule_layer_map_rule_id_layer_pk" PRIMARY KEY("rule_id","layer")
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
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "stack_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "threat" (
	"public_id" text PRIMARY KEY NOT NULL,
	"family" "threat_family" NOT NULL,
	"name" text NOT NULL,
	"severity" "severity_level",
	"description" text,
	"ai_amplification" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
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
ALTER TABLE "rule_ide" ADD CONSTRAINT "rule_ide_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_ide" ADD CONSTRAINT "rule_ide_ide_id_ide_id_fk" FOREIGN KEY ("ide_id") REFERENCES "public"."ide"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rule_layer_map" ADD CONSTRAINT "rule_layer_map_rule_id_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rule"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
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
CREATE UNIQUE INDEX "content_revision_entity_sha" ON "content_revision" USING btree ("entity_type","entity_id","git_sha");