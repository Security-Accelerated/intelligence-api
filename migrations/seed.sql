-- Example seed data for local development. Not auto-run in production.

INSERT INTO customers (id, name) VALUES
    (1, 'Test Admin'),
    (2, 'Test Lookup User'),
    (3, 'Test Typosquatting User'),
    (4, 'Test Enterprise User')
ON CONFLICT (name) DO NOTHING;

INSERT INTO api_keys (customer_id, key_hash) VALUES
    (1, encode(digest('test-admin-key', 'sha256'), 'hex')),
    (2, encode(digest('test-lookup-key', 'sha256'), 'hex')),
    (3, encode(digest('test-typosquatting-key', 'sha256'), 'hex')),
    (4, encode(digest('test-enterprise-key', 'sha256'), 'hex'))
ON CONFLICT (customer_id) DO NOTHING;

INSERT INTO customer_features (customer_id, feature) VALUES
    (1, 'admin'),
    (2, 'lookup'),
    (3, 'typosquatting'),
    (4, 'lookup'),
    (4, 'typosquatting')
ON CONFLICT (customer_id, feature) DO NOTHING;

UPDATE customers SET tier = 'premium' WHERE name IN ('Test Admin', 'Test Typosquatting User', 'Test Enterprise User');
