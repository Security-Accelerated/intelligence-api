-- Example seed data for local development. Not auto-run in production.

INSERT INTO customers (id, name) VALUES
    (1, 'Test Admin'),
    (2, 'Test Domain User')
ON CONFLICT (name) DO NOTHING;

INSERT INTO api_keys (customer_id, key_hash) VALUES
    (1, encode(digest('test-admin-key', 'sha256'), 'hex')),
    (2, encode(digest('test-domain-key', 'sha256'), 'hex'))
ON CONFLICT (customer_id) DO NOTHING;

INSERT INTO customer_roles (customer_id, role) VALUES
    (1, 'admin'),
    (1, 'domain'),
    (2, 'domain')
ON CONFLICT (customer_id, role) DO NOTHING;

UPDATE customers SET tier = 'premium' WHERE name = 'Test Admin';
