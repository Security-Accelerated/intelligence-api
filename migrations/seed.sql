-- Example seed data for local development. Not auto-run in production.
-- Insert a test admin key and a test domain-only key.
INSERT INTO api_keys (key, role) VALUES
    ('test-admin-key', 'admin'),
    ('test-domain-key', 'domain')
ON CONFLICT (key) DO NOTHING;
