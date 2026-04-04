package app

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/viper"
)

func openDB(ctx context.Context, cfg *viper.Viper) (*sql.DB, error) {
	// Build a postgres:// URL so pgx can parse it natively.
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.GetString("postgres.user"),
		cfg.GetString("postgres.password"),
		cfg.GetString("postgres.host"),
		cfg.GetInt("postgres.port"),
		cfg.GetString("postgres.dbname"),
		cfg.GetString("postgres.sslmode"),
	)

	// Parse the DSN into a pgx config so we can set simple protocol mode.
	// Simple protocol avoids prepared statements, which Neon's serverless
	// pooler (PgBouncer in transaction mode) invalidates between requests.
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	connConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Register the config with pgx/stdlib and open via database/sql.
	connStr := stdlib.RegisterConnConfig(connConfig)
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(cfg.GetInt("postgres.max_open_conns"))
	db.SetMaxIdleConns(cfg.GetInt("postgres.max_idle_conns"))
	db.SetConnMaxLifetime(cfg.GetDuration("postgres.conn_max_lifetime"))
	db.SetConnMaxIdleTime(cfg.GetDuration("postgres.conn_max_idle_time"))

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
