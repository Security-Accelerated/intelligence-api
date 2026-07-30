-- IP lookups are now individually selectable, so they are tracked alongside the
-- domain ones. threat_intel already has a column (migration 009) and is shared
-- between the two endpoints.
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS geo           BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS asn           BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS reverse_dns   BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS abuse_contact BOOLEAN NOT NULL DEFAULT FALSE;
