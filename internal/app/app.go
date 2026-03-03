package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/httpapi"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/service"
	"go.uber.org/zap"
)


// Run wires up all dependencies and runs the server until shutdown.
func Run(logger *zap.Logger, version string) error {
	cfg := config.Config()

	port := cfg.GetInt("application.port")
	rlCfg := middleware.RateLimitConfig{
		Basic:   cfg.GetInt("rate_limit.basic"),
		Premium: cfg.GetInt("rate_limit.premium"),
	}

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
		zap.Int("rate_limit_basic", rlCfg.Basic),
		zap.Int("rate_limit_premium", rlCfg.Premium),
		zap.String("redis_addr", cfg.GetString("redis.addr")),
		zap.Int("redis_db", cfg.GetInt("redis.db")),
		zap.String("postgres_host", cfg.GetString("postgres.host")),
		zap.Int("postgres_port", cfg.GetInt("postgres.port")),
		zap.String("postgres_dbname", cfg.GetString("postgres.dbname")),
		zap.String("postgres_sslmode", cfg.GetString("postgres.sslmode")),
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
	cachedRepo := auth.NewCachedRepository(authRepo, cfg.GetDuration("auth.cache_ttl"))

	// Cache
	redisCache := cache.NewRedisCache(
		cfg.GetString("redis.addr"),
		cfg.GetString("redis.password"),
		cfg.GetInt("redis.db"),
	)
	defer redisCache.Close()

	if err := redisCache.Ping(ctx); err != nil {
		return fmt.Errorf("connect to redis: %w", err)
	}
	logger.Info("connected to redis")

	// Services
	cacheTTL := cfg.GetDuration("redis.cache_ttl")
	domainService := service.NewDomainService(redisCache, cacheTTL, cfg.GetDuration("screenshot.timeout"))
	typosquattingService := service.NewTyposquattingService(
		redisCache, cacheTTL, cfg.GetDuration("typosquatting.timeout"),
		cfg.GetInt("typosquatting.max_permutations"),
		cfg.GetInt("typosquatting.concurrency"),
	)

	// HTTP
	h := handler.New(domainService, typosquattingService, version)
	router := httpapi.NewRouter(h, cachedRepo, redisCache.Client(), rlCfg, cfg.GetString("application.mode"))
	server := httpapi.NewServer(router, port)

	// Shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := httpapi.Serve(server, sigCh, cancel, logger); err != nil {
		return err
	}

	logger.Info("application stopped")
	return nil
}
