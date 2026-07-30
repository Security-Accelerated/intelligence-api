-- Per-lookup cache metrics replace the per-request cache_hit boolean. A single
-- request can now serve some lookups from cache and fetch others live, so hits
-- and misses are counted individually.
ALTER TABLE request_log ADD COLUMN cache_hits   INT NOT NULL DEFAULT 0;
ALTER TABLE request_log ADD COLUMN cache_misses INT NOT NULL DEFAULT 0;
ALTER TABLE request_log DROP COLUMN IF EXISTS cache_hit;

-- The four base lookups are now individually selectable, so they are tracked
-- alongside the optional ones for feature-usage analytics.
ALTER TABLE request_log ADD COLUMN whois   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN dns     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN ssl     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN headers BOOLEAN NOT NULL DEFAULT FALSE;
