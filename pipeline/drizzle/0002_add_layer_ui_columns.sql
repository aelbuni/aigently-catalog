ALTER TABLE "layer" ADD COLUMN "description" text NOT NULL DEFAULT '';--> statement-breakpoint
ALTER TABLE "layer" ADD COLUMN "icon_name" text;--> statement-breakpoint
ALTER TABLE "layer" ADD COLUMN "color_token" text;--> statement-breakpoint
ALTER TABLE "layer" ADD COLUMN "is_system" boolean NOT NULL DEFAULT false;--> statement-breakpoint
ALTER TABLE "layer" ADD COLUMN "created_at" timestamp with time zone NOT NULL DEFAULT now();--> statement-breakpoint
ALTER TABLE "layer" ADD COLUMN "updated_at" timestamp with time zone NOT NULL DEFAULT now();
