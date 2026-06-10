-- Migration: add EPSS exploit-prediction columns to threat
-- EPSS (FIRST.org Exploit Prediction Scoring System) provides a daily-updated
-- probability that a given CVE will be exploited within the next 30 days.
-- Both fields are nullable: fresh CVEs (< 24h old) often lack EPSS data, and
-- pre-existing rows backfill on the next sync.

ALTER TABLE threat ADD COLUMN IF NOT EXISTS epss_score double precision;
ALTER TABLE threat ADD COLUMN IF NOT EXISTS epss_percentile double precision;
