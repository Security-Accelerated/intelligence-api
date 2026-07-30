-- Per-lookup cache metrics replace the per-request cache_hit boolean. A single
-- request can now serve some lookups from cache and fetch others live, so hits
-- and misses are counted individually.
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS cache_hits   INT NOT NULL DEFAULT 0;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS cache_misses INT NOT NULL DEFAULT 0;
-- Dropping the old cache_hit column lives in migration 016, deliberately. This
-- file is additive only, so it can be applied to a running deployment before
-- the code that uses the new columns ships.

-- The four base lookups are now individually selectable, so they are tracked
-- alongside the optional ones for feature-usage analytics.
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS whois   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS dns     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS ssl     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS headers BOOLEAN NOT NULL DEFAULT FALSE;

-- The aggregate risk score is now an opt-in lookup, so it is tracked like the
-- rest. dns_security already has a column from migration 013.
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS risk BOOLEAN NOT NULL DEFAULT FALSE;
