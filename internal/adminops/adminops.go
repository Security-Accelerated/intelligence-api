// Package adminops holds the database operations behind the sactl admin CLI.
//
// It is deliberately separate from internal/billing. That package's
// ProvisionCustomer is shaped for Stripe checkout: it writes a provisioned_keys
// row so the plaintext can be retrieved exactly once from the success page.
// The CLI prints the key to the operator directly, so persisting a second copy
// of it would create a retrievable secret nobody is going to collect.
package adminops

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/billing"
)

// ErrNotFound is returned when an operation targets a customer that does not exist.
var ErrNotFound = errors.New("customer not found")

// Store runs admin operations against PostgreSQL.
type Store struct {
	db *sql.DB
}

// NewStore returns a Store backed by db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// Customer is a customer row plus the state of its keys, as the CLI reports it.
type Customer struct {
	ID        int
	Name      string
	Email     string
	Plan      string
	Active    bool
	CreatedAt time.Time
	// LiveKeys counts keys that are currently usable: not expired, or expiring
	// in the future during a rotation grace window.
	LiveKeys int
	// LastUsedAt is the most recent use across the customer's keys, zero if never.
	LastUsedAt time.Time
}

// Key is an api_keys row. The plaintext is never stored, so it cannot be listed
// — only the hash prefix, which is enough to correlate with a key an operator
// already holds.
type Key struct {
	ID         int
	HashPrefix string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// Expired reports whether the key's grace window has already closed.
func (k Key) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && k.ExpiresAt.Before(now)
}

// CreateCustomer creates a customer and its first API key in one transaction,
// returning the plaintext key. The plaintext exists only in the return value:
// it is not logged and not persisted, so an operator who loses it must rotate
// rather than look it up.
func (s *Store) CreateCustomer(ctx context.Context, name, email, plan string) (customerID int, rawKey string, err error) {
	// Trim first: a whitespace-only name passes an equality check against "" and
	// is stored verbatim, leaving a customer whose name renders as blank in
	// every listing and which nothing downstream corrects.
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, "", errors.New("name is required")
	}
	if !auth.ValidPlan(plan) {
		return 0, "", fmt.Errorf("invalid plan %q; valid plans: %v", plan, auth.Plans)
	}

	rawKey, err = billing.GenerateAPIKey()
	if err != nil {
		return 0, "", err
	}
	keyHash := auth.HashKey(rawKey)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err == nil {
			return
		}
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback transaction: %w", rbErr))
		}
	}()

	// NULLIF keeps an omitted email as NULL rather than an empty string, so
	// "no email" is one value in the column instead of two.
	err = tx.QueryRowContext(ctx,
		`INSERT INTO customers (name, email, plan, active, created_at)
		 VALUES ($1, NULLIF($2, ''), $3, true, now())
		 RETURNING id`,
		name, email, plan,
	).Scan(&customerID)
	if err != nil {
		return 0, "", fmt.Errorf("insert customer: %w", err)
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO api_keys (customer_id, key_hash, created_at)
		 VALUES ($1, $2, now())`,
		customerID, keyHash,
	); err != nil {
		return 0, "", fmt.Errorf("insert api key: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, "", fmt.Errorf("commit: %w", err)
	}
	return customerID, rawKey, nil
}

// ListCustomers returns every customer with its key state, oldest first.
func (s *Store) ListCustomers(ctx context.Context) ([]Customer, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.id, c.name, COALESCE(c.email, ''), c.plan, c.active, c.created_at,
		        COUNT(k.id) FILTER (WHERE k.expires_at IS NULL OR k.expires_at > now()),
		        MAX(k.last_used_at)
		   FROM customers c
		   LEFT JOIN api_keys k ON k.customer_id = c.id
		  GROUP BY c.id
		  ORDER BY c.id`)
	if err != nil {
		return nil, fmt.Errorf("list customers: %w", err)
	}
	defer rows.Close()

	var out []Customer
	for rows.Next() {
		var c Customer
		var lastUsed sql.NullTime
		if err := rows.Scan(&c.ID, &c.Name, &c.Email, &c.Plan, &c.Active, &c.CreatedAt, &c.LiveKeys, &lastUsed); err != nil {
			return nil, fmt.Errorf("scan customer: %w", err)
		}
		if lastUsed.Valid {
			c.LastUsedAt = lastUsed.Time
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListKeys returns a customer's keys, newest first.
func (s *Store) ListKeys(ctx context.Context, customerID int) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, LEFT(key_hash, 12), created_at, last_used_at, expires_at
		   FROM api_keys
		  WHERE customer_id = $1
		  ORDER BY created_at DESC, id DESC`, customerID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer rows.Close()

	var out []Key
	for rows.Next() {
		var k Key
		var lastUsed, expires sql.NullTime
		if err := rows.Scan(&k.ID, &k.HashPrefix, &k.CreatedAt, &lastUsed, &expires); err != nil {
			return nil, fmt.Errorf("scan key: %w", err)
		}
		if lastUsed.Valid {
			k.LastUsedAt = lastUsed.Time
		}
		if expires.Valid {
			k.ExpiresAt = expires.Time
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetPlan changes a customer's plan. The caller is responsible for invalidating
// the auth cache afterwards; until it expires, the running service keeps
// serving the old plan.
func (s *Store) SetPlan(ctx context.Context, customerID int, plan string) error {
	if !auth.ValidPlan(plan) {
		return fmt.Errorf("invalid plan %q; valid plans: %v", plan, auth.Plans)
	}
	return s.exec(ctx, `UPDATE customers SET plan = $1 WHERE id = $2`, plan, customerID)
}

// SetActive activates or deactivates a customer. Deactivating rejects the
// customer's keys at the next auth lookup without deleting anything, so it is
// reversible.
func (s *Store) SetActive(ctx context.Context, customerID int, active bool) error {
	return s.exec(ctx, `UPDATE customers SET active = $1 WHERE id = $2`, active, customerID)
}

// exec runs a statement that must affect exactly one customer, reporting
// ErrNotFound when it matched nothing. Without the rows-affected check an
// operation against a mistyped ID would report success having changed nothing.
func (s *Store) exec(ctx context.Context, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
