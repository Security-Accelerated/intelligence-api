package app

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/httpapi"
	"github.com/security-accelerated/intelligence-api/internal/service"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Run wires up all dependencies and runs the server until shutdown.
func Run(logger *zap.Logger, version string) error {
	cfg := config.Config()

	port := cfg.GetInt("application.port")
	logger.Info("initializing application",
		zap.String("start_time", cfg.GetString("application.start.time")),
		zap.String("application_name", cfg.GetString("application.name")),
		zap.String("session_id", cfg.GetString("application.session.id")),
		zap.String("environment", cfg.GetString("application.mode")),
		zap.Int("port", port),
		zap.String("host", cfg.GetString("environment.host")),
		zap.String("golang_version", cfg.GetString("environment.golang.version")),
		zap.String("architecture", cfg.GetString("environment.architecture")),
		zap.String("os", cfg.GetString("environment.os")),
		zap.String("version", version),
		zap.Duration("cache_ttl", cfg.GetDuration("redis.cache_ttl")),
		zap.Duration("auth_cache_ttl", cfg.GetDuration("auth.cache_ttl")),
		zap.Duration("screenshot_timeout", cfg.GetDuration("screenshot.timeout")),
		zap.Duration("typosquatting_timeout", cfg.GetDuration("typosquatting.timeout")),
		zap.Int("typosquatting_max_permutations", cfg.GetInt("typosquatting.max_permutations")),
		zap.Int("typosquatting_concurrency", cfg.GetInt("typosquatting.concurrency")),
		zap.String("gin_mode", cfg.GetString("gin.mode")),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	db, err := openDB(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer db.Close()
	logger.Info("connected to postgres")

	// Auth
	authRepo := auth.NewPostgresRepository(db)
	authCacheTTL := cfg.GetDuration("auth.cache_ttl")
	if authCacheTTL == 0 {
		authCacheTTL = 5 * time.Minute
	}
	cachedRepo := auth.NewCachedRepository(authRepo, authCacheTTL)

	// Cache
	redisCache := cache.NewRedisCache(
		cfg.GetString("redis.addr"),
		cfg.GetString("redis.password"),
		cfg.GetInt("redis.db"),
	)

	// Services
	cacheTTL := cfg.GetDuration("redis.cache_ttl")

	screenshotTimeout := cfg.GetDuration("screenshot.timeout")
	if screenshotTimeout == 0 {
		screenshotTimeout = 15 * time.Second
	}
	domainService := service.NewDomainService(redisCache, cacheTTL, screenshotTimeout)

	typosquattingTimeout := cfg.GetDuration("typosquatting.timeout")
	if typosquattingTimeout == 0 {
		typosquattingTimeout = 30 * time.Second
	}
	typosquattingService := service.NewTyposquattingService(
		redisCache, cacheTTL, typosquattingTimeout,
		cfg.GetInt("typosquatting.max_permutations"),
		cfg.GetInt("typosquatting.concurrency"),
	)

	// HTTP
	h := handler.New(domainService, typosquattingService, version)
	router := httpapi.NewRouter(ctx, h, cachedRepo, cfg.GetString("application.mode"))
	server := httpapi.NewServer(router, port)

	// Shutdown signal
	shutdown := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		cancel()
		close(shutdown)
	}()

	if err := httpapi.Serve(server, shutdown, logger); err != nil {
		return err
	}

	logger.Info("application stopped")
	return nil
}

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
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
