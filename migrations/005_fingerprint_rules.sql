CREATE TABLE IF NOT EXISTS fingerprint_rules (
    id         SERIAL PRIMARY KEY,
    rules      JSONB NOT NULL,
    updated_by INTEGER REFERENCES api_keys(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
