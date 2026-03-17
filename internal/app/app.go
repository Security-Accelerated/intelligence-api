package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/billing"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/httpapi"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"github.com/security-accelerated/intelligence-api/internal/service"
	"go.uber.org/zap"
)


// Run wires up all dependencies and runs the server until shutdown.
func Run(logger *zap.Logger, version string) error {
	cfg := config.Config()

	port := cfg.GetInt("application.port")
	rlCfg := middleware.RateLimitConfig{
		Free:  cfg.GetInt("rate_limit.free"),
		Basic: cfg.GetInt("rate_limit.basic"),
		Pro:   cfg.GetInt("rate_limit.pro"),
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
		zap.Int("domain_max_domains_free", cfg.GetInt("domain.max_domains.free")),
		zap.Int("domain_max_domains_basic", cfg.GetInt("domain.max_domains.basic")),
		zap.Int("domain_max_domains_pro", cfg.GetInt("domain.max_domains.pro")),
		zap.Int("subdomain_max_results", cfg.GetInt("subdomain.max_results")),
		zap.Int("ct_logs_max_entries", cfg.GetInt("ct_logs.max_entries")),
		zap.Int("rate_limit_free", rlCfg.Free),
		zap.Int("rate_limit_basic", rlCfg.Basic),
		zap.Int("rate_limit_pro", rlCfg.Pro),
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

	// Notifications
	var alerter notifications.ErrorRecorder
	var notifier notifications.Notifier
	pushoverToken := cfg.GetString("pushover.api_token")
	pushoverUser := cfg.GetString("pushover.user_key")
	if pushoverToken != "" && pushoverUser != "" {
		notifier = notifications.NewPushoverNotifier(pushoverToken, pushoverUser)
		alerter = notifications.NewAlerter(notifier, notifications.AlerterConfig{
			ThrottleThreshold: cfg.GetInt("alerts.throttle_threshold"),
			ThrottleWindow:    cfg.GetDuration("alerts.throttle_window"),
			SpikeThreshold:    cfg.GetInt("alerts.spike_threshold"),
			SpikeWindow:       cfg.GetDuration("alerts.spike_window"),
			Cooldown:          cfg.GetDuration("alerts.cooldown"),
		})
		logger.Info("pushover notifications enabled")
	} else {
		notifier = &notifications.NoopNotifier{}
		alerter = &notifications.NoopRecorder{}
		logger.Info("pushover notifications disabled (no credentials configured)")
	}

	// Services
	cacheTTL := cfg.GetDuration("redis.cache_ttl")

	fpService := service.NewFingerprintService(db)
	if err := fpService.LoadFromDB(ctx); err != nil {
		logger.Warn("failed to load fingerprint rules from DB, using embedded defaults", zap.Error(err))
		defaults, defErr := domain.DefaultRules()
		if defErr == nil {
			fpService.Engine().LoadRules(defaults)
		}
	}
	logger.Info("fingerprint engine loaded", zap.Int("rule_count", fpService.Engine().RuleCount()))

	domainService := service.NewDomainService(redisCache, cacheTTL, cfg.GetDuration("screenshot.timeout"), cfg.GetInt("subdomain.max_results"), cfg.GetInt("ct_logs.max_entries"), fpService.Engine(), alerter)

	// Billing
	var billingSvc billing.Service
	stripeKey := cfg.GetString("stripe.secret_key")
	webhookSecret := cfg.GetString("stripe.webhook_secret")
	if stripeKey != "" && webhookSecret != "" {
		priceMap := make(map[string]string)
		if p := cfg.GetString("stripe.prices.basic_monthly"); p != "" {
			priceMap[p] = "basic"
		}
		if p := cfg.GetString("stripe.prices.pro_monthly"); p != "" {
			priceMap[p] = "pro"
		}
		billingRepo := billing.NewRepository(db)
		billingSvc = billing.NewStripeService(stripeKey, webhookSecret, priceMap, billingRepo, cachedRepo, notifier)
		logger.Info("stripe billing enabled")
	} else {
		billingSvc = &billing.NoopService{}
		logger.Info("stripe billing disabled (no credentials configured)")
	}

	// HTTP
	h := handler.New(domainService, fpService, billingSvc, version, cfg, redisCache, cachedRepo)
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
