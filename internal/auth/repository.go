package auth

import (
	"context"
	"database/sql"
)

type Repository interface {
	GetByKey(ctx context.Context, key string) (*Customer, error)
}

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) GetByKey(ctx context.Context, key string) (*Customer, error) {
	keyHash := HashKey(key)
	var c Customer
	err := r.db.QueryRowContext(ctx,
		`SELECT ak.id, c.id, c.name, c.active, c.plan, c.created_at
		   FROM api_keys ak
		   JOIN customers c ON c.id = ak.customer_id
		  WHERE ak.key_hash = $1 AND c.active = true`,
		keyHash,
	).Scan(&c.APIKeyID, &c.ID, &c.Name, &c.Active, &c.Plan, &c.CreatedAt)
	if err != nil {
		return nil, err
	}

	// Update last_used_at in background (fire-and-forget)
	go func() {
		_, _ = r.db.Exec(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, c.APIKeyID)
	}()

	return &c, nil
}
