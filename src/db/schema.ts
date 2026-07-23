import { pgTable, serial, text, varchar, integer, timestamp, jsonb, boolean } from "drizzle-orm/pg-core";

export const analysisReports = pgTable("analysis_reports", {
  id: serial("id").primaryKey(),
  reportId: varchar("report_id", { length: 64 }).notNull().unique(),
  riskScore: integer("risk_score").notNull(),
  riskLevel: varchar("risk_level", { length: 32 }).notNull(), // 'critical' | 'caution' | 'safe'
  senderDisplay: varchar("sender_display", { length: 255 }),
  senderDomain: varchar("sender_domain", { length: 255 }),
  targetBrand: varchar("target_brand", { length: 128 }),
  extractedDomains: jsonb("extracted_domains").$type<string[]>().default([]),
  extractedUrls: jsonb("extracted_urls").$type<string[]>().default([]),
  threatFactors: jsonb("threat_factors").$type<
    Array<{
      id: string;
      title: string;
      severity: "critical" | "high" | "medium" | "low" | "positive";
      impactScore: number;
      explanation: string;
      technicalEvidence: string;
    }>
  >().default([]),
  aiSummary: text("ai_summary").notNull(),
  likelyObjective: varchar("likely_objective", { length: 255 }),
  recommendationAction: varchar("recommendation_action", { length: 64 }).notNull(),
  recommendationText: text("recommendation_text").notNull(),
  inputType: varchar("input_type", { length: 32 }).default("text"),
  processingTimeMs: integer("processing_time_ms").default(0),
  thumbsUp: integer("thumbs_up").default(0),
  thumbsDown: integer("thumbs_down").default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const threatIntelligenceCache = pgTable("threat_intelligence_cache", {
  id: serial("id").primaryKey(),
  domainOrUrl: varchar("domain_or_url", { length: 512 }).notNull().unique(),
  sourceType: varchar("source_type", { length: 32 }).notNull(),
  intelData: jsonb("intel_data").notNull(),
  isMalicious: boolean("is_malicious").default(false),
  cachedAt: timestamp("cached_at", { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

export const threatFeedItems = pgTable("threat_feed_items", {
  id: serial("id").primaryKey(),
  threatTitle: varchar("threat_title", { length: 255 }).notNull(),
  targetBrand: varchar("target_brand", { length: 128 }).notNull(),
  domainDetected: varchar("domain_detected", { length: 255 }).notNull(),
  riskScore: integer("risk_score").notNull(),
  threatCategory: varchar("threat_category", { length: 64 }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const userFeedback = pgTable("user_feedback", {
  id: serial("id").primaryKey(),
  reportId: varchar("report_id", { length: 64 }).notNull(),
  feedbackType: varchar("feedback_type", { length: 16 }).notNull(), // 'up' | 'down'
  feedbackReason: text("feedback_reason"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
