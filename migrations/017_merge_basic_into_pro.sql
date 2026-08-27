-- Collapse the plan model from three paid-ish tiers to two: free and pro.
-- 'basic' sat between them (30 req/min, 5 targets per request) and is no longer
-- a plan the code recognizes — auth.Plans, the rate limiter, and the per-plan
-- caps all dropped it.
--
-- Existing basic customers move UP to pro rather than down to free, so the
-- merge never takes capability away from anyone who already had it.
--
-- APPLY THIS BEFORE DEPLOYING THE BUILD THAT REMOVES THE PLAN. The ordering is
-- not symmetric. Applied first, this is harmless to the running service: the
-- old build understands 'pro' and 'free' as well as it understood 'basic'.
-- Deployed first, every surviving basic row becomes an unrecognized plan —
-- planRank has no entry for it, so lookup gating reads it as free, and the rate
-- limiter falls back to free — and a basic customer silently drops to 5 req/min
-- and one domain per request until this runs.
UPDATE customers SET plan = 'pro' WHERE plan = 'basic';

-- Migration 002 created this column as `tier ... DEFAULT 'basic'` and 006
-- renamed it to `plan`, carrying the default along. Left alone, any INSERT that
-- omits plan would keep minting customers on a plan nothing understands; the
-- rate limiter would fall back to free limits while lookup gating also treated
-- them as free, so the row would work but never match what was intended.
-- Free is the right default for an unspecified plan: least privileged.
ALTER TABLE customers ALTER COLUMN plan SET DEFAULT 'free';
