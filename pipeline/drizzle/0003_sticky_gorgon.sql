CREATE TYPE "public"."stack_catalog_status" AS ENUM('launch', 'coming_soon');--> statement-breakpoint
ALTER TABLE "rule" ADD COLUMN "summary_mdx" text;--> statement-breakpoint
ALTER TABLE "stack" ADD COLUMN "catalog_status" "stack_catalog_status" DEFAULT 'launch' NOT NULL;