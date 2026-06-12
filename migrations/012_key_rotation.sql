-- Self-service API key rotation: a customer may briefly hold multiple keys
-- (the new one plus old ones expiring after a grace window).
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_customer_id_key;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS api_keys_customer_id_idx ON api_keys (customer_id);
