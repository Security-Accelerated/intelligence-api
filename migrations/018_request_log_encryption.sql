-- Encryption posture lookups (POST /v1/encryption/lookup) are tracked like the
-- domain and IP ones: one boolean per lookup requested, plus a count of the
-- hosts submitted. host_count is separate from domain_count so usage of the
-- two endpoints can be queried independently, as ip_count is (migration 011).
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS host_count   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS protocols    BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS key_exchange BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS certificate  BOOLEAN NOT NULL DEFAULT FALSE;
