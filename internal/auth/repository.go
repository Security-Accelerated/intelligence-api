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
	var c Customer
	err := r.db.QueryRowContext(ctx,
		`SELECT c.id, c.name, c.active, c.created_at
		   FROM api_keys ak
		   JOIN customers c ON c.id = ak.customer_id
		  WHERE ak.key = $1 AND c.active = true`,
		key,
	).Scan(&c.ID, &c.Name, &c.Active, &c.CreatedAt)
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
