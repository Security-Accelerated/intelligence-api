package auth

import (
	"context"
	"database/sql"
)

type Repository interface {
	GetByKey(ctx context.Context, key string) (*APIKey, error)
}

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) GetByKey(ctx context.Context, key string) (*APIKey, error) {
	var ak APIKey
	err := r.db.QueryRowContext(ctx,
		`SELECT id, key, role, active, created_at FROM api_keys WHERE key = $1 AND active = true`,
		key,
	).Scan(&ak.ID, &ak.Key, &ak.Role, &ak.Active, &ak.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ak, nil
}
