CREATE TABLE IF NOT EXISTS api_keys (
    id          SERIAL PRIMARY KEY,
    key         VARCHAR(64) UNIQUE NOT NULL,
    role        VARCHAR(32) NOT NULL DEFAULT 'domain',
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
