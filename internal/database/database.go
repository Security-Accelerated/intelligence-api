// Package database opens the service's PostgreSQL connection.
//
// It lives outside internal/app because both the API server and the sactl admin
// CLI connect to the same database, and the connection carries a non-obvious
// requirement (see Open) that a second, hand-rolled implementation would get
// wrong silently rather than loudly.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/viper"
)

// DSN returns the connection string to use.
//
// postgres.url wins when set. Managed providers (Neon, Fly, Heroku) issue a
// complete URL, and splitting one into host/user/password/dbname only to
// reassemble it here is a lossy round trip: connection parameters carried in
// the query string — endpoint IDs, channel binding, pooler options — are
// dropped, and the failure shows up as an authentication error rather than as
// missing configuration.
//
// Everything else is assembled from the individual postgres.* keys.
func DSN(cfg *viper.Viper) string {
	if raw := strings.TrimSpace(cfg.GetString("postgres.url")); raw != "" {
		return raw
	}
	// Build a postgres:// URL with proper percent-encoding so credentials
	// containing reserved URI characters (@, /, #, %, etc.) are handled safely.
	return (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.GetString("postgres.user"), cfg.GetString("postgres.password")),
		Host:     fmt.Sprintf("%s:%d", cfg.GetString("postgres.host"), cfg.GetInt("postgres.port")),
		Path:     cfg.GetString("postgres.dbname"),
		RawQuery: "sslmode=" + url.QueryEscape(cfg.GetString("postgres.sslmode")),
	}).String()
}

// Describe returns a human-readable "host/dbname" for the configured target,
// with any credentials removed. Admin tooling prints it before mutating
// anything, so an operator can see which database they are about to change.
func Describe(cfg *viper.Viper) string {
	u, err := url.Parse(DSN(cfg))
	if err != nil {
		return "(unparseable connection string)"
	}
	// Hostname() rather than Host: with nothing configured the assembled DSN is
	// "postgres://:@:0/", whose Host is ":0" — non-empty, but naming no server.
	// Printing that as the target reads as a rendering bug rather than as
	// missing configuration.
	if u.Hostname() == "" {
		return "(no database configured)"
	}
	return u.Host + strings.TrimSuffix(u.Path, "/")
}

// Open connects to PostgreSQL using the postgres.* configuration keys, applies
// the pool limits, and verifies the connection with a ping before returning.
func Open(ctx context.Context, cfg *viper.Viper) (*sql.DB, error) {
	connStr, err := connString(cfg)
	if err != nil {
		return nil, err
	}

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

// connString builds the DSN and registers it with pgx/stdlib, returning the
// name database/sql should open.
func connString(cfg *viper.Viper) (string, error) {
	dsn := DSN(cfg)

	// Parse the DSN into a pgx config so we can set simple protocol mode.
	// Simple protocol avoids prepared statements, which Neon's serverless
	// pooler (PgBouncer in transaction mode) invalidates between requests.
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "", fmt.Errorf("parse postgres dsn: %w", err)
	}
	connConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	return stdlib.RegisterConnConfig(connConfig), nil
}
