-- Add ip_count column to request_log for IP lookup analytics.
-- Separate from domain_count so usage can be queried independently.
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS ip_count INTEGER NOT NULL DEFAULT 0;
