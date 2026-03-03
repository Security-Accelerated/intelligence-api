CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE api_keys ADD COLUMN key_hash VARCHAR(64);

UPDATE api_keys SET key_hash = encode(digest(key, 'sha256'), 'hex');

ALTER TABLE api_keys ALTER COLUMN key_hash SET NOT NULL;

ALTER TABLE api_keys ADD CONSTRAINT api_keys_key_hash_unique UNIQUE (key_hash);

ALTER TABLE api_keys DROP COLUMN key;
