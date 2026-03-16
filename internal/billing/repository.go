package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrKeyNotFound = errors.New("provisioned key not found")
	ErrKeyRetrieved = errors.New("key has already been retrieved")
	ErrKeyExpired  = errors.New("provisioned key has expired")
)

// Repository handles billing-related database operations.
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new billing repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// CreateCustomerWithKey creates a customer and an API key in a single transaction.
// Returns the new customer ID.
func (r *Repository) CreateCustomerWithKey(ctx context.Context, name, email, plan, stripeCustomerID, keyHash string) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var customerID int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO customers (name, email, stripe_customer_id, plan, active, created_at)
		 VALUES ($1, $2, $3, $4, true, now())
		 RETURNING id`,
		name, email, stripeCustomerID, plan,
	).Scan(&customerID)
	if err != nil {
		return 0, fmt.Errorf("insert customer: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO api_keys (customer_id, key_hash, created_at)
		 VALUES ($1, $2, now())`,
		customerID, keyHash,
	)
	if err != nil {
		return 0, fmt.Errorf("insert api key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return customerID, nil
}

// StoreProvisionedKey stores a raw API key for one-time retrieval after checkout.
func (r *Repository) StoreProvisionedKey(ctx context.Context, sessionID string, customerID int, rawKey string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO provisioned_keys (session_id, customer_id, raw_key, created_at, expires_at)
		 VALUES ($1, $2, $3, now(), now() + INTERVAL '1 hour')`,
		sessionID, customerID, rawKey,
	)
	if err != nil {
		return fmt.Errorf("store provisioned key: %w", err)
	}
	return nil
}

// RetrieveProvisionedKey retrieves a provisioned key by session ID, marks it as retrieved,
// and returns the raw key. Returns an error if the key has already been retrieved or has expired.
func (r *Repository) RetrieveProvisionedKey(ctx context.Context, sessionID string) (string, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var rawKey string
	var retrieved bool
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT raw_key, retrieved, expires_at FROM provisioned_keys WHERE session_id = $1`,
		sessionID,
	).Scan(&rawKey, &retrieved, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrKeyNotFound
		}
		return "", fmt.Errorf("query provisioned key: %w", err)
	}

	if retrieved {
		return "", ErrKeyRetrieved
	}
	if time.Now().After(expiresAt) {
		return "", ErrKeyExpired
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE provisioned_keys SET retrieved = true WHERE session_id = $1`,
		sessionID,
	)
	if err != nil {
		return "", fmt.Errorf("mark retrieved: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	return rawKey, nil
}

// UpdatePlan updates a customer's plan by their Stripe customer ID.
func (r *Repository) UpdatePlan(ctx context.Context, stripeCustomerID, plan string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE customers SET plan = $1 WHERE stripe_customer_id = $2 AND active = true`,
		plan, stripeCustomerID,
	)
	if err != nil {
		return fmt.Errorf("update plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no active customer found with stripe_customer_id %s", stripeCustomerID)
	}
	return nil
}

// DowngradeToFree downgrades a customer to the free plan by their Stripe customer ID.
func (r *Repository) DowngradeToFree(ctx context.Context, stripeCustomerID string) error {
	return r.UpdatePlan(ctx, stripeCustomerID, "free")
}

// CleanupExpiredKeys deletes expired provisioned keys.
func (r *Repository) CleanupExpiredKeys(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM provisioned_keys WHERE expires_at < now()`,
	)
	if err != nil {
		return fmt.Errorf("cleanup expired keys: %w", err)
	}
	return nil
}

// DeactivateStaleKeys deactivates customers whose API keys have not been used
// since the cutoff time (or were created before the cutoff and never used).
// Returns the number of deactivated customers.
func (r *Repository) DeactivateStaleKeys(ctx context.Context, cutoff time.Time) (int, error) {
	result, err := r.db.ExecContext(ctx,
		`UPDATE customers SET active = false
		 WHERE active = true AND plan != 'admin' AND id IN (
			SELECT c.id FROM customers c
			JOIN api_keys ak ON ak.customer_id = c.id
			WHERE c.active = true AND c.plan != 'admin'
			  AND (ak.last_used_at IS NULL AND ak.created_at < $1)
			   OR (ak.last_used_at IS NOT NULL AND ak.last_used_at < $1)
		 )`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("deactivate stale keys: %w", err)
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// CustomerExistsByStripeID checks if a customer already exists with the given Stripe customer ID.
func (r *Repository) CustomerExistsByStripeID(ctx context.Context, stripeCustomerID string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM customers WHERE stripe_customer_id = $1)`,
		stripeCustomerID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check customer exists: %w", err)
	}
	return exists, nil
}
