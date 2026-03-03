ALTER TABLE customer_roles RENAME TO customer_features;
ALTER TABLE customer_features RENAME COLUMN role TO feature;
