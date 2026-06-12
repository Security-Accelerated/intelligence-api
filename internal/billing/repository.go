package billing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrKeyNotFound  = errors.New("provisioned key not found")
	ErrKeyRetrieved = errors.New("key has already been retrieved")
	ErrKeyExpired   = errors.New("provisioned key has expired")
)

// Repository handles billing-related database operations.
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new billing repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// ProvisionCustomer creates a customer, API key, and provisioned key in a single
// transaction. This ensures all three records exist atomically — a partial failure
// cannot leave a customer without a retrievable API key.
// Returns the new customer ID.
func (r *Repository) ProvisionCustomer(ctx context.Context, name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey string) (customerID int, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback transaction: %w", rbErr))
		}
	}()

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

	_, err = tx.ExecContext(ctx,
		`INSERT INTO provisioned_keys (session_id, customer_id, raw_key, created_at, expires_at)
		 VALUES ($1, $2, $3, now(), now() + INTERVAL '1 hour')`,
		sessionID, customerID, rawKey,
	)
	if err != nil {
		return 0, fmt.Errorf("insert provisioned key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return customerID, nil
}

// RetrieveProvisionedKey atomically marks a provisioned key as retrieved and returns it.
// Returns an error if the key has already been retrieved, has expired, or does not exist.
func (r *Repository) RetrieveProvisionedKey(ctx context.Context, sessionID string) (string, error) {
	var rawKey string
	err := r.db.QueryRowContext(ctx,
		`UPDATE provisioned_keys
		    SET retrieved = true
		  WHERE session_id = $1
		    AND retrieved = false
		    AND expires_at > now()
		  RETURNING raw_key`,
		sessionID,
	).Scan(&rawKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", r.classifyRetrievalError(ctx, sessionID)
		}
		return "", fmt.Errorf("retrieve provisioned key: %w", err)
	}
	return rawKey, nil
}

// classifyRetrievalError checks why the atomic UPDATE matched no rows and returns
// the appropriate sentinel error.
func (r *Repository) classifyRetrievalError(ctx context.Context, sessionID string) error {
	var retrieved bool
	var expiresAt time.Time
	err := r.db.QueryRowContext(ctx,
		`SELECT retrieved, expires_at FROM provisioned_keys WHERE session_id = $1`,
		sessionID,
	).Scan(&retrieved, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("classify retrieval error: %w", err)
	}
	if retrieved {
		return ErrKeyRetrieved
	}
	if time.Now().After(expiresAt) {
		return ErrKeyExpired
	}
	return ErrKeyNotFound
}

// RotateKey inserts a new API key for the customer and sets every other key
// of that customer to expire at graceExpiry (never extending an expiry that is
// already sooner). Both steps run in one transaction so a failure can't leave
// the customer with their old key expired and no replacement.
func (r *Repository) RotateKey(ctx context.Context, customerID int, newKeyHash string, graceExpiry time.Time) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback transaction: %w", rbErr))
		}
	}()

	var newKeyID int
	err = tx.QueryRowContext(ctx,
		`INSERT INTO api_keys (customer_id, key_hash, created_at)
		 VALUES ($1, $2, now())
		 RETURNING id`,
		customerID, newKeyHash,
	).Scan(&newKeyID)
	if err != nil {
		return fmt.Errorf("insert rotated api key: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE api_keys
		    SET expires_at = $1
		  WHERE customer_id = $2
		    AND id != $3
		    AND (expires_at IS NULL OR expires_at > $1)`,
		graceExpiry, customerID, newKeyID,
	)
	if err != nil {
		return fmt.Errorf("expire previous api keys: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
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
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update plan rows affected: %w", err)
	}
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

// DeactivateStaleKeys deactivates customers none of whose live (non-expired)
// API keys have been used since the cutoff time (counting never-used keys by
// creation date). A customer with any fresh key stays active — rotation can
// leave multiple keys per customer. Returns the number of deactivated customers.
func (r *Repository) DeactivateStaleKeys(ctx context.Context, cutoff time.Time) (int, error) {
	result, err := r.db.ExecContext(ctx,
		`UPDATE customers SET active = false
		 WHERE active = true AND plan != 'admin'
		   AND EXISTS (
			SELECT 1 FROM api_keys ak
			WHERE ak.customer_id = customers.id
		   )
		   AND NOT EXISTS (
			SELECT 1 FROM api_keys ak
			WHERE ak.customer_id = customers.id
			  AND (ak.expires_at IS NULL OR ak.expires_at > now())
			  AND ((ak.last_used_at IS NULL AND ak.created_at >= $1)
			    OR (ak.last_used_at IS NOT NULL AND ak.last_used_at >= $1))
		 )`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("deactivate stale keys: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("deactivate stale keys rows affected: %w", err)
	}
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
