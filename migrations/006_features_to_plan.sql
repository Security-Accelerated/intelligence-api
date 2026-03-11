-- Migrate from two-dimensional access control (tier + features) to single plan column.
-- Plans: basic, pro, admin.

-- Promote admin-featured customers to 'admin' plan, enterprise to 'pro'.
UPDATE customers SET tier = 'admin'
  WHERE id IN (SELECT customer_id FROM customer_features WHERE feature = 'admin');

UPDATE customers SET tier = 'pro'
  WHERE tier = 'premium' AND id NOT IN (SELECT customer_id FROM customer_features WHERE feature = 'admin');

-- Rename tier → plan.
ALTER TABLE customers RENAME COLUMN tier TO plan;

-- Drop the features table — no longer needed.
DROP TABLE IF EXISTS customer_features;
