package app

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/viper"
)

func openDB(ctx context.Context, cfg *viper.Viper) (*sql.DB, error) {
	// Build a postgres:// URL with proper percent-encoding so credentials
	// containing reserved URI characters (@, /, #, %, etc.) are handled safely.
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.GetString("postgres.user"), cfg.GetString("postgres.password")),
		Host:     fmt.Sprintf("%s:%d", cfg.GetString("postgres.host"), cfg.GetInt("postgres.port")),
		Path:     cfg.GetString("postgres.dbname"),
		RawQuery: "sslmode=" + url.QueryEscape(cfg.GetString("postgres.sslmode")),
	}).String()

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
