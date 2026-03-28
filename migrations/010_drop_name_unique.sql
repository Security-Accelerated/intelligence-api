-- Drop the unique constraint on customers.name. The name column was made unique
-- before billing existed; now that Stripe checkout populates it with the
-- customer's real name, two people with the same name would collide.
-- stripe_customer_id is already the correct uniqueness anchor.
ALTER TABLE customers DROP CONSTRAINT IF EXISTS customers_name_key;
