-- Example seed data for local development. Not auto-run in production.

INSERT INTO customers (id, name, plan) VALUES
    (1, 'Test Admin', 'admin'),
    (2, 'Test Basic User', 'basic'),
    (3, 'Test Pro User', 'pro'),
    (4, 'Test Free User', 'free'),
    (5, 'Test Free User 2', 'free')
ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan;

INSERT INTO api_keys (customer_id, key_hash) VALUES
    (1, encode(digest('test-admin-key', 'sha256'), 'hex')),
    (2, encode(digest('test-basic-key', 'sha256'), 'hex')),
    (3, encode(digest('test-pro-key', 'sha256'), 'hex')),
    (4, encode(digest('test-free-key', 'sha256'), 'hex')),
    (5, encode(digest('test-free-key-2', 'sha256'), 'hex'))
ON CONFLICT (customer_id) DO NOTHING;
