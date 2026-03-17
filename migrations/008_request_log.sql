CREATE TABLE IF NOT EXISTS request_log (
    id             BIGSERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    customer_id    INT,
    api_key_id     INT,
    plan           TEXT,
    method         TEXT NOT NULL,
    path           TEXT NOT NULL,
    status_code    INT NOT NULL,
    latency_ms     INT NOT NULL,
    domain_count   INT NOT NULL DEFAULT 0,
    cache_hit      BOOLEAN NOT NULL DEFAULT FALSE,
    screenshot     BOOLEAN NOT NULL DEFAULT FALSE,
    reputation     BOOLEAN NOT NULL DEFAULT FALSE,
    email_security BOOLEAN NOT NULL DEFAULT FALSE,
    subdomains     BOOLEAN NOT NULL DEFAULT FALSE,
    ct_logs        BOOLEAN NOT NULL DEFAULT FALSE,
    bgp            BOOLEAN NOT NULL DEFAULT FALSE,
    fingerprint    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_request_log_created_at  ON request_log (created_at);
CREATE INDEX idx_request_log_customer_id ON request_log (customer_id);
CREATE INDEX idx_request_log_api_key_id  ON request_log (api_key_id);
