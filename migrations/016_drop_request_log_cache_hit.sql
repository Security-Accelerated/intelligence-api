-- Contract step for migration 014. Run this only AFTER a build that no longer
-- writes request_log.cache_hit is deployed (v0.55.0 or later).
--
-- Applying it early breaks the running service: releases up to v0.53.0 name
-- cache_hit explicitly in their usage INSERT, so every usage write would fail
-- until the new build ships. Because 014 is additive, the two schemas overlap —
-- old and new builds both work while this column still exists — which is what
-- lets the deploy happen in either order. This drop closes that window and is
-- irreversible.
ALTER TABLE request_log DROP COLUMN IF EXISTS cache_hit;
