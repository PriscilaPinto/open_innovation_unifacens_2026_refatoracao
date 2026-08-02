-- ==========================================
-- Migration: Add virtual patch columns
-- Table: vulnerability_records
-- Requirements: 8.2
-- ==========================================
-- Idempotent: safe to re-run (ADD COLUMN IF NOT EXISTS)

ALTER TABLE vulnerability_records
    ADD COLUMN IF NOT EXISTS virtual_patch_path TEXT,
    ADD COLUMN IF NOT EXISTS virtual_patch_data  TEXT;
