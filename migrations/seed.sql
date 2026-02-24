-- Example seed data for local development. Not auto-run in production.

INSERT INTO customers (id, name) VALUES
    (1, 'Test Admin'),
    (2, 'Test Domain User')
ON CONFLICT (name) DO NOTHING;

INSERT INTO api_keys (customer_id, key) VALUES
    (1, 'test-admin-key'),
    (2, 'test-domain-key')
ON CONFLICT (key) DO NOTHING;

INSERT INTO customer_roles (customer_id, role) VALUES
    (1, 'admin'),
    (1, 'domain'),
    (2, 'domain')
ON CONFLICT (customer_id, role) DO NOTHING;

UPDATE customers SET tier = 'premium' WHERE name = 'Test Admin';
