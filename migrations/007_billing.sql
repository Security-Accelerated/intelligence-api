ALTER TABLE customers ADD COLUMN IF NOT EXISTS email VARCHAR(255);
ALTER TABLE customers ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(64) UNIQUE;

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS provisioned_keys (
    id          SERIAL PRIMARY KEY,
    session_id  VARCHAR(128) UNIQUE NOT NULL,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    raw_key     VARCHAR(64) NOT NULL,
    retrieved   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '1 hour'
);
