package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"go.uber.org/zap"
)

// Run wires up all dependencies and runs the server until shutdown.
func Run(logger *zap.Logger, version string) error {
	logger = logger.With(zap.String("version", version))
	cfg := config.Config()

	status := config.NewStatusSnapshot(version)

	rlCfg := middleware.RateLimitConfig{
		Free:  cfg.GetInt("rate_limit.free"),
		Basic: cfg.GetInt("rate_limit.basic"),
		Pro:   cfg.GetInt("rate_limit.pro"),
	}

	// DNS resolver — use external resolvers to avoid platform DNS issues (e.g., Fly.io)
	dnsServers := cfg.GetStringSlice("dns.servers")
	domain.InitResolver(dnsServers)
	if len(dnsServers) == 0 {
		dnsServers = domain.DefaultDNSServers
	}
	logger.Info("dns resolver configured", zap.Strings("servers", dnsServers))

	logger.Info("initializing application",
		zap.Any("system", status.System),
		zap.Any("lookups", status.Lookups),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	db, err := openDB(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("postgres close failed", zap.Error(err))
		}
	}()
	logger.Info("connected to postgres", zap.Any("config", status.Database))

	// Auth
	lastUsedBatcher := auth.NewLastUsedBatcher(
		db,
		cfg.GetInt("auth.last_used_buffer_size"),
		cfg.GetDuration("auth.last_used_flush_interval"),
		logger,
	)
	defer lastUsedBatcher.Stop()
	authRepo := auth.NewPostgresRepository(db, lastUsedBatcher)
	cachedRepo := auth.NewCachedRepository(authRepo, cfg.GetDuration("auth.cache_ttl"))

	// Cache
	redisCache := cache.NewRedisCache(
		cfg.GetString("redis.addr"),
		cfg.GetString("redis.password"),
		cfg.GetInt("redis.db"),
	)
	defer func() {
		if err := redisCache.Close(); err != nil {
			logger.Error("redis close failed", zap.Error(err))
		}
	}()

	if err := redisCache.Ping(ctx); err != nil {
		return fmt.Errorf("connect to redis: %w", err)
	}
	logger.Info("connected to redis", zap.Any("config", status.Cache))

	// Notifications
	var alerter notifications.ErrorRecorder
	var notifier notifications.Notifier
	pushoverToken := cfg.GetString("pushover.api_token")
	pushoverUser := cfg.GetString("pushover.user_key")
	if pushoverToken != "" && pushoverUser != "" {
		notifier = notifications.NewPushoverNotifier(pushoverToken, pushoverUser)
		alerter = notifications.NewAlerter(notifier, notifications.AlerterConfig{
			ThrottleThreshold:  cfg.GetInt("alerts.throttle_threshold"),
			ThrottleWindow:     cfg.GetDuration("alerts.throttle_window"),
			SpikeThreshold:     cfg.GetInt("alerts.spike_threshold"),
			SpikeWindow:        cfg.GetDuration("alerts.spike_window"),
			Cooldown:           cfg.GetDuration("alerts.cooldown"),
			MaxConcurrentSends: cfg.GetInt("alerts.max_concurrent_sends"),
			MaxWindowSize:      cfg.GetInt("alerts.max_window_size"),
		})
		status.Services.Notifications = config.NotificationsStatus{
			Enabled:            true,
			ThrottleThreshold:  cfg.GetInt("alerts.throttle_threshold"),
			ThrottleWindow:     cfg.GetDuration("alerts.throttle_window").String(),
			SpikeThreshold:     cfg.GetInt("alerts.spike_threshold"),
			SpikeWindow:        cfg.GetDuration("alerts.spike_window").String(),
			Cooldown:           cfg.GetDuration("alerts.cooldown").String(),
			MaxConcurrentSends: cfg.GetInt("alerts.max_concurrent_sends"),
			MaxWindowSize:      cfg.GetInt("alerts.max_window_size"),
		}
		logger.Info("pushover notifications enabled", zap.Any("config", status.Services.Notifications))
	} else {
		notifier = &notifications.NoopNotifier{}
		alerter = &notifications.NoopRecorder{}
		logger.Info("pushover notifications disabled (no credentials configured)")
	}
	if a, ok := alerter.(*notifications.Alerter); ok {
		defer a.Close()
	}

	// Services
	cacheTTL := cfg.GetDuration("redis.cache_ttl")

	fpService := service.NewFingerprintService(db)
	fpSource := "database"
	if err := fpService.LoadFromDB(ctx); err != nil {
		logger.Warn("failed to load fingerprint rules from DB, using embedded defaults", zap.Error(err))
		fpSource = "embedded"
		defaults, defErr := domain.DefaultRules()
		if defErr != nil {
			return fmt.Errorf("load embedded fingerprint defaults: %w", defErr)
		}
		fpService.Engine().LoadRules(defaults)
	}
	status.Services.Fingerprint = config.FingerprintStatus{
		Source:    fpSource,
		RuleCount: fpService.Engine().RuleCount(),
	}
	logger.Info("fingerprint engine loaded", zap.Any("config", status.Services.Fingerprint))

	// Threat intelligence providers — built based on config.
	var tiProviders []domain.ThreatIntelProvider
	if vtKey := cfg.GetString("threat_intel.virustotal_api_key"); vtKey != "" {
		tiProviders = append(tiProviders, domain.NewVirusTotalProvider(vtKey))
	}
	tiProviders = append(tiProviders, domain.NewURLhausProvider()) // always enabled (no key)
	if otxKey := cfg.GetString("threat_intel.alienvault_api_key"); otxKey != "" {
		tiProviders = append(tiProviders, domain.NewAlienVaultProvider(otxKey))
	}
	tiNames := make([]string, len(tiProviders))
	for i, p := range tiProviders {
		tiNames[i] = p.Name()
	}
	status.Services.ThreatIntel = config.ThreatIntelStatus{
		ProviderCount: len(tiProviders),
		Providers:     tiNames,
	}
	logger.Info("threat intelligence providers loaded", zap.Any("config", status.Services.ThreatIntel))

	// Set configurable limits on domain package vars before constructing the service.
	if v := cfg.GetInt("screenshot.max_png_bytes"); v > 0 {
		domain.DefaultMaxPNGBytes = v
	}
	if v := cfg.GetInt64("subdomain.max_response_bytes"); v > 0 {
		domain.MaxResponseBody = v
	}

	domainService := service.NewDomainService(redisCache, cacheTTL, cfg.GetDuration("domain.lookup_timeout"), cfg.GetDuration("screenshot.timeout"), cfg.GetInt("subdomain.max_results"), cfg.GetInt("ct_logs.max_entries"), fpService.Engine(), alerter, tiProviders)

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
		status.Services.Billing = config.BillingStatus{
			Enabled:              true,
			PortalLinkConfigured: cfg.GetString("stripe.portal_link") != "",
			StaleKeyDays:         cfg.GetInt("billing.stale_key_days"),
		}
		logger.Info("stripe billing enabled", zap.Any("config", status.Services.Billing))
	} else {
		billingSvc = &billing.NoopService{}
		logger.Info("stripe billing disabled (no credentials configured)")
	}

	// Usage tracking
	usageLogger := usage.NewUsageLogger(
		db,
		cfg.GetInt("usage.buffer_size"),
		cfg.GetDuration("usage.flush_interval"),
		logger,
	)
	defer usageLogger.Stop()
	usageQuerySvc := usage.NewQueryService(db)
	status.Services.Usage = config.UsageStatus{
		BufferSize:    cfg.GetInt("usage.buffer_size"),
		FlushInterval: cfg.GetDuration("usage.flush_interval").String(),
	}
	logger.Info("usage tracking enabled", zap.Any("config", status.Services.Usage))

	// GeoIP reader — always created so the admin refresh endpoint can bootstrap
	// databases on fresh deployments. Lookups gracefully return errors until
	// databases are loaded (either from disk at startup or via admin refresh).
	dbPath := cfg.GetString("maxmind.db_path")
	cityPath := filepath.Join(dbPath, cfg.GetString("maxmind.city_db"))
	asnPath := filepath.Join(dbPath, cfg.GetString("maxmind.asn_db"))
	var geoReader *domain.GeoIPReader
	if _, err := os.Stat(cityPath); err == nil {
		geoReader, err = domain.NewGeoIPReader(cityPath, asnPath)
		if err != nil {
			logger.Warn("failed to load MaxMind databases, using empty reader", zap.Error(err))
			geoReader = domain.NewEmptyGeoIPReader()
		} else {
			geoStatus := config.GeoIPStatus{
				Enabled: true,
				CityDB:  cfg.GetString("maxmind.city_db"),
				ASNDB:   cfg.GetString("maxmind.asn_db"),
				DBPath:  dbPath,
			}
			status.SetGeoIPStatus(geoStatus)
			logger.Info("geoip databases loaded", zap.Any("config", geoStatus))
		}
	} else {
		geoReader = domain.NewEmptyGeoIPReader()
		logger.Info("geoip databases not found, use POST /v1/admin/geoip/refresh to bootstrap", zap.String("path", cityPath))
	}
	defer func() {
		if err := geoReader.Close(); err != nil {
			logger.Error("geoip reader close failed", zap.Error(err))
		}
	}()

	// IP threat intel providers (adapters around the domain providers)
	var ipTIProviders []domain.IPThreatIntelProvider
	for _, p := range tiProviders {
		switch tp := p.(type) {
		case *domain.VirusTotalProvider:
			ipTIProviders = append(ipTIProviders, domain.NewVTIPProvider(tp))
		case *domain.URLhausProvider:
			ipTIProviders = append(ipTIProviders, domain.NewURLhausIPProvider(tp))
		case *domain.AlienVaultProvider:
			ipTIProviders = append(ipTIProviders, domain.NewOTXIPProvider(tp))
		}
	}

	// IP intelligence service
	ipService := service.NewIPService(redisCache, cacheTTL, cfg.GetDuration("ip.lookup_timeout"), geoReader, alerter, ipTIProviders)

	// HTTP
	h := handler.New(domainService, ipService, fpService, billingSvc, usageQuerySvc, geoReader, cfg, redisCache, cachedRepo, db, status)
	router := httpapi.NewRouter(h, cachedRepo, redisCache.Client(), rlCfg, usageLogger, cfg.GetString("application.mode"), int64(cfg.GetInt("server.body_limit")))
	serverCfg := httpapi.ServerConfig{
		Port:            status.System.Port,
		ReadTimeout:     cfg.GetDuration("server.read_timeout"),
		WriteTimeout:    cfg.GetDuration("server.write_timeout"),
		IdleTimeout:     cfg.GetDuration("server.idle_timeout"),
		ShutdownTimeout: cfg.GetDuration("server.shutdown_timeout"),
	}
	server := httpapi.NewServer(router, serverCfg)

	// Shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	if err := httpapi.Serve(server, sigCh, cancel, logger, serverCfg.ShutdownTimeout); err != nil {
		return err
	}

	logger.Info("application stopped")
	return nil
}
