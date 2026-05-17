import { sql } from "drizzle-orm";
import {
  boolean,
  date,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

/** Auth.js default PostgreSQL schema — table names match @auth/drizzle-adapter */
export const user = pgTable("user", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  name: text("name"),
  email: text("email").unique(),
  emailVerified: timestamp("emailVerified", { mode: "date" }),
  image: text("image"),
});

export const account = pgTable(
  "account",
  {
    userId: text("userId")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    provider: text("provider").notNull(),
    providerAccountId: text("providerAccountId").notNull(),
    refresh_token: text("refresh_token"),
    access_token: text("access_token"),
    expires_at: integer("expires_at"),
    token_type: text("token_type"),
    scope: text("scope"),
    id_token: text("id_token"),
    session_state: text("session_state"),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.provider, t.providerAccountId] }),
  })
);

export const session = pgTable("session", {
  sessionToken: text("sessionToken").primaryKey(),
  userId: text("userId")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  expires: timestamp("expires", { mode: "date" }).notNull(),
});

export const verificationToken = pgTable(
  "verificationToken",
  {
    identifier: text("identifier").notNull(),
    token: text("token").notNull(),
    expires: timestamp("expires", { mode: "date" }).notNull(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.identifier, t.token] }),
  })
);

export const authenticator = pgTable(
  "authenticator",
  {
    credentialID: text("credentialID").notNull().unique(),
    userId: text("userId")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    providerAccountId: text("providerAccountId").notNull(),
    credentialPublicKey: text("credentialPublicKey").notNull(),
    counter: integer("counter").notNull(),
    credentialDeviceType: text("credentialDeviceType").notNull(),
    credentialBackedUp: boolean("credentialBackedUp").notNull(),
    transports: text("transports"),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.userId, t.credentialID] }),
  })
);

export const threatFamilyEnum = pgEnum("threat_family", [
  "owasp_web",
  "owasp_llm",
  "mitre_atlas",
  "vibe_coding",
]);

export const severityLevelEnum = pgEnum("severity_level", [
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export const ruleLayerEnum = pgEnum("rule_layer", [
  "security",
  "architecture",
  "code_quality",
]);

/** Upsert / provenance for ingested vs curated threats (PRD §3, ADR 0001). */
export const threatSourceEnum = pgEnum("threat_source", [
  "nvd",
  "osv",
  "ghsa",
  "cisa_kev",
  "aigently",
  "mitre_atlas",
  "aigently_internal",
]);

export const frameworkFeatureStatusEnum = pgEnum("framework_feature_status", [
  "built_in",
  "manual_cfg",
  "not_supported",
]);

export const stackCatalogStatusEnum = pgEnum("stack_catalog_status", ["launch", "coming_soon"]);

export const stack = pgTable("stack", {
  id: smallint("id").primaryKey().generatedAlwaysAsIdentity(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  logoPath: text("logo_path"),
  sortOrder: smallint("sort_order").notNull().default(0),
  catalogStatus: stackCatalogStatusEnum("catalog_status").notNull().default("launch"),
  securityGrade: text("security_grade"),
  gradeRationale: text("grade_rationale"),
  ecosystem: text("ecosystem"),
  nvdKeywords: text("nvd_keywords")
    .array()
    .notNull()
    .default(sql`ARRAY[]::text[]`),
  osvEcosystem: text("osv_ecosystem"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const ide = pgTable("ide", {
  id: smallint("id").primaryKey().generatedAlwaysAsIdentity(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  sortOrder: smallint("sort_order").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const threat = pgTable("threat", {
  publicId: text("public_id").primaryKey(),
  family: threatFamilyEnum("family").notNull(),
  name: text("name").notNull(),
  severity: severityLevelEnum("severity"),
  description: text("description"),
  aiAmplification: text("ai_amplification"),
  details: jsonb("details").notNull().default({}),
  cveId: text("cve_id"),
  /** Stable upsert key for OSV/GHSA/NVD; curated rows may mirror public_id after backfill. */
  externalId: text("external_id").unique(),
  source: threatSourceEnum("source").notNull().default("aigently"),
  sourceUrl: text("source_url"),
  publishedAt: timestamp("published_at", { withTimezone: true }),
  syncedAt: timestamp("synced_at", { withTimezone: true }),
  mitreAttackIds: text("mitre_attack_ids")
    .array()
    .notNull()
    .default(sql`ARRAY[]::text[]`),
  owaspRefs: text("owasp_refs")
    .array()
    .notNull()
    .default(sql`ARRAY[]::text[]`),
  affectedProducts: jsonb("affected_products").notNull().default({}),
  patchedVersion: text("patched_version"),
  isActivelyExploited: boolean("is_actively_exploited").notNull().default(false),
  cisaActionDue: text("cisa_action_due"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const rule = pgTable("rule", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  version: text("version").notNull(),
  dateAdded: date("date_added").notNull(),
  lastUpdated: date("last_updated").notNull(),
  author: text("author").notNull(),
  certified: boolean("certified").notNull().default(false),
  complexity: text("complexity"),
  lineCount: integer("line_count"),
  ruleType: text("rule_type", { enum: ["pattern", "deps", "config", "runtime"] }),
  strengthScore: integer("strength_score").notNull().default(0),
  contentPath: text("content_path"),
  bodyMdx: text("body_mdx"),
  summaryMdx: text("summary_mdx"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const ruleStack = pgTable(
  "rule_stack",
  {
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
    stackId: smallint("stack_id")
      .notNull()
      .references(() => stack.id, { onDelete: "cascade" }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.ruleId, t.stackId] }),
  })
);

export const ruleIde = pgTable(
  "rule_ide",
  {
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
    ideId: smallint("ide_id")
      .notNull()
      .references(() => ide.id, { onDelete: "cascade" }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.ruleId, t.ideId] }),
  })
);

/** First-class layer entity — slug-keyed, replaces the hardcoded ruleLayerEnum in rule_layer_map. */
export const layer = pgTable("layer", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  concernStatement: text("concern_statement").notNull().default(""),
  isActive: boolean("is_active").notNull().default(true),
  sortOrder: integer("sort_order").notNull().default(100),
});

/** Maps threats to protection layers (primary/secondary relevance). */
export const threatLayer = pgTable(
  "threat_layer",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    threatId: text("threat_id")
      .notNull()
      .references(() => threat.publicId, { onDelete: "cascade" }),
    layerId: uuid("layer_id")
      .notNull()
      .references(() => layer.id, { onDelete: "cascade" }),
    relevance: text("relevance", { enum: ["primary", "secondary"] }).notNull().default("primary"),
    rationale: text("rationale"),
    addedAt: timestamp("added_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    uniq: uniqueIndex("uq_threat_layer").on(t.threatId, t.layerId),
  })
);

export const ruleLayerMap = pgTable(
  "rule_layer_map",
  {
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
    layerId: uuid("layer_id")
      .notNull()
      .references(() => layer.id, { onDelete: "cascade" }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.ruleId, t.layerId] }),
  })
);

export const ruleSeverityTag = pgTable(
  "rule_severity_tag",
  {
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
    severity: severityLevelEnum("severity").notNull(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.ruleId, t.severity] }),
  })
);

export const ruleThreatMap = pgTable(
  "rule_threat_map",
  {
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
    threatId: text("threat_id")
      .notNull()
      .references(() => threat.publicId, { onDelete: "restrict" }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.ruleId, t.threatId] }),
  })
);

/** Per-stack threat severity / mitigation matrix (PRD Screen 2). */
export const threatStack = pgTable(
  "threat_stack",
  {
    threatId: text("threat_id")
      .notNull()
      .references(() => threat.publicId, { onDelete: "cascade" }),
    stackId: smallint("stack_id")
      .notNull()
      .references(() => stack.id, { onDelete: "cascade" }),
    severity: severityLevelEnum("severity").notNull(),
    isMitigatedByRules: boolean("is_mitigated_by_rules").notNull().default(false),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.threatId, t.stackId] }),
  })
);

export const stackCoverageArea = pgTable(
  "stack_coverage_area",
  {
    id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
    stackId: smallint("stack_id")
      .notNull()
      .references(() => stack.id, { onDelete: "cascade" }),
    areaName: text("area_name").notNull(),
    coveragePercent: smallint("coverage_percent"),
    notes: text("notes"),
  },
  (t) => ({
    stackAreaUniq: uniqueIndex("stack_coverage_area_stack_area").on(t.stackId, t.areaName),
  })
);

export const stackFrameworkFeature = pgTable(
  "stack_framework_feature",
  {
    id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
    stackId: smallint("stack_id")
      .notNull()
      .references(() => stack.id, { onDelete: "cascade" }),
    featureName: text("feature_name").notNull(),
    status: frameworkFeatureStatusEnum("status").notNull(),
    notes: text("notes"),
  },
  (t) => ({
    stackFeatureUniq: uniqueIndex("stack_framework_feature_stack_feature").on(
      t.stackId,
      t.featureName
    ),
  })
);

export const syncLog = pgTable("sync_log", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
  sourceSummary: jsonb("source_summary").notNull().default({}),
  coveragePercent: smallint("coverage_percent"),
  status: text("status").notNull().default("running"),
  errorMessage: text("error_message"),
});

/** AI-synthesized guardrail content per (stack, layer) pair. Written by the catalog pipeline CI and readable by the admin dashboard. */
export const summarizedGuardrail = pgTable("summarized_guardrail", {
  id: uuid("id").primaryKey().defaultRandom(),
  stackId: smallint("stack_id").notNull().references(() => stack.id),
  layerId: uuid("layer_id").notNull().references(() => layer.id),
  ideSlug: text("ide_slug").notNull().default("all"),
  content: text("content").notNull(),
  sourceRuleIds: uuid("source_rule_ids").array().notNull(),
  provenance: jsonb("provenance"),
  conflictCount: integer("conflict_count").notNull().default(0),
  cacheKey: text("cache_key").notNull().unique(),
  summarizerVersion: text("summarizer_version").notNull(),
  generatedAt: timestamp("generated_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  qualityScore: smallint("quality_score").notNull().default(0),
  scoreOverride: smallint("score_override"),
  scoreNote: text("score_note"),
});

export const policyTemplate = pgTable("policy_template", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  description: text("description"),
  layer: ruleLayerEnum("layer").notNull(),
  bodyMarkdown: text("body_markdown"),
  sortOrder: smallint("sort_order").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const policyTemplateStack = pgTable(
  "policy_template_stack",
  {
    templateId: integer("template_id")
      .notNull()
      .references(() => policyTemplate.id, { onDelete: "cascade" }),
    stackId: smallint("stack_id")
      .notNull()
      .references(() => stack.id, { onDelete: "cascade" }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.templateId, t.stackId] }),
  })
);

export const article = pgTable("article", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  title: text("title").notNull(),
  excerpt: text("excerpt"),
  readingMinutes: smallint("reading_minutes"),
  publishedAt: timestamp("published_at", { withTimezone: true }),
  tags: text("tags")
    .array()
    .notNull()
    .default(sql`ARRAY[]::text[]`),
  contentPath: text("content_path"),
  bodyMdx: text("body_mdx"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const articleRuleMap = pgTable(
  "article_rule_map",
  {
    articleId: uuid("article_id")
      .notNull()
      .references(() => article.id, { onDelete: "cascade" }),
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.articleId, t.ruleId] }),
  })
);

export const ruleReview = pgTable("rule_review", {
  id: uuid("id").primaryKey().defaultRandom(),
  ruleId: uuid("rule_id")
    .notNull()
    .references(() => rule.id, { onDelete: "cascade" }),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  rating: smallint("rating").notNull(),
  reviewText: text("review_text").notNull(),
  ideUsed: text("ide_used").notNull(),
  stackTested: text("stack_tested").notNull(),
  helpfulCount: integer("helpful_count").notNull().default(0),
  authorHandle: text("author_handle"),
  isVerified: boolean("is_verified").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const ruleReviewHelpful = pgTable(
  "rule_review_helpful",
  {
    reviewId: uuid("review_id")
      .notNull()
      .references(() => ruleReview.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.reviewId, t.userId] }),
  })
);

export const articleFeedback = pgTable(
  "article_feedback",
  {
    articleId: uuid("article_id")
      .notNull()
      .references(() => article.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    helpful: boolean("helpful").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.articleId, t.userId] }),
  })
);

export const ruleUsageDaily = pgTable(
  "rule_usage_daily",
  {
    ruleId: uuid("rule_id")
      .notNull()
      .references(() => rule.id, { onDelete: "cascade" }),
    bucketDate: date("bucket_date").notNull(),
    copyCount: integer("copy_count").notNull().default(0),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.ruleId, t.bucketDate] }),
  })
);

export const contentRevision = pgTable(
  "content_revision",
  {
    id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
    entityType: text("entity_type").notNull(),
    entityId: uuid("entity_id").notNull(),
    gitSha: text("git_sha").notNull(),
    syncedAt: timestamp("synced_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    entityShaUniq: uniqueIndex("content_revision_entity_sha").on(
      t.entityType,
      t.entityId,
      t.gitSha
    ),
  })
);
