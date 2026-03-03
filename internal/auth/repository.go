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
		`SELECT ak.id, c.id, c.name, c.active, c.tier, c.created_at
		   FROM api_keys ak
		   JOIN customers c ON c.id = ak.customer_id
		  WHERE ak.key_hash = $1 AND c.active = true`,
		keyHash,
	).Scan(&c.APIKeyID, &c.ID, &c.Name, &c.Active, &c.Tier, &c.CreatedAt)
	if err != nil {
		return nil, err
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT role FROM customer_roles WHERE customer_id = $1`, c.ID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		c.Roles = append(c.Roles, role)
	}
	return &c, rows.Err()
}
