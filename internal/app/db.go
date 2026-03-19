package app

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

func openDB(ctx context.Context, cfg *viper.Viper) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.GetString("postgres.host"),
		cfg.GetInt("postgres.port"),
		cfg.GetString("postgres.user"),
		cfg.GetString("postgres.password"),
		cfg.GetString("postgres.dbname"),
		cfg.GetString("postgres.sslmode"),
	)
	db, err := sql.Open("postgres", dsn)
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
