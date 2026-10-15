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
	"github.com/security-accelerated/intelligence-api/internal/database"
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

	// Both catalogs, so /info reports the same TTL table the services resolve.
	lookupNames := append(append([]string{}, domain.AllLookupNames...), domain.AllIPLookupNames...)

	status := config.NewStatusSnapshot(version, lookupNames)

	rlCfg := middleware.RateLimitConfig{
		Free: cfg.GetInt("rate_limit.free"),
		Pro:  cfg.GetInt("rate_limit.pro"),
	}

	logger.Info("initializing application",
		zap.Any("system", status.System),
		zap.Any("lookups", status.Lookups),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	db, closeDB, err := database.Open(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer func() {
		if err := closeDB(); err != nil {
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

	// DNS resolver for intelligence lookups. Scoped to the domain package via
	// domain.Resolver(), so this no longer has to run after Postgres and Redis
	// connect: net.DefaultResolver is untouched and platform-internal hostnames
	// keep resolving through the system resolver for the life of the process.
	// The old ordering requirement only ever protected the *initial*
	// connections, and pooled reconnects failed once they aged out (issue #62).
	dnsServers := cfg.GetStringSlice("dns.servers")
	dnsTimeout := cfg.GetDuration("dns.timeout")
	domain.InitResolver(dnsServers, dnsTimeout)
	if len(dnsServers) == 0 {
		dnsServers = domain.DefaultDNSServers
	}
	logger.Info("dns resolver configured", zap.Strings("servers", dnsServers), zap.Duration("dial_timeout", domain.DefaultDNSDialTimeout))

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
	defaultCacheTTL := config.DefaultCacheTTL(cfg)
	cacheTTLs := config.CacheTTLs(cfg, lookupNames)
	// Neither service negative-caches any more: with per-lookup TTLs, one flaky
	// provider can no longer shorten everything else's lifetime, and a failing
	// lookup is better retried than remembered.

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
	if v := cfg.GetInt64("subdomain.max_response_bytes"); v > 0 {
		domain.MaxResponseBody = v
	}
	if v := cfg.GetDuration("subdomain.http_timeout"); v > 0 {
		domain.SubdomainHTTPTimeout = v
	}
	if v := cfg.GetDuration("ct_logs.http_timeout"); v > 0 {
		domain.CTLogsHTTPTimeout = v
	}

	domainService := service.NewDomainService(redisCache, defaultCacheTTL, cacheTTLs, cfg.GetDuration("domain.lookup_timeout"), cfg.GetInt("subdomain.max_results"), cfg.GetInt("ct_logs.max_entries"), fpService.Engine(), alerter, tiProviders)

	// Billing
	billingRepo := billing.NewRepository(db)
	var billingSvc billing.Service
	stripeKey := cfg.GetString("stripe.secret_key")
	webhookSecret := cfg.GetString("stripe.webhook_secret")
	if stripeKey != "" && webhookSecret != "" {
		priceMap := make(map[string]string)
		if p := cfg.GetString("stripe.prices.pro_monthly"); p != "" {
			priceMap[p] = "pro"
		}
		billingSvc = billing.NewStripeService(stripeKey, webhookSecret, priceMap, billingRepo, cachedRepo, notifier)
		status.Services.Billing = config.BillingStatus{
			Enabled:              true,
			Mode:                 billing.KeyMode(stripeKey),
			PortalLinkConfigured: cfg.GetString("stripe.portal_link") != "",
			StaleKeyDays:         cfg.GetInt("billing.stale_key_days"),
		}
		logger.Info("stripe billing enabled", zap.Any("config", status.Services.Billing))
		// A test key in production is a half-finished go-live: checkout works,
		// nothing is charged, and no error is raised anywhere. Say so once at
		// startup; /v1/info carries the same field for later checks.
		if status.Services.Billing.Mode != billing.ModeLive && cfg.GetString("application.mode") == "production" {
			logger.Warn("stripe billing is not in live mode in production",
				zap.String("mode", status.Services.Billing.Mode))
		}
	} else {
		billingSvc = &billing.NoopService{}
		logger.Info("stripe billing disabled (no credentials configured)")
	}

	// Expired provisioned keys hold plaintext for never-retrieved sessions —
	// sweep them on an interval regardless of whether Stripe is configured.
	billing.StartProvisionedKeyCleanup(ctx, billingRepo, cfg.GetDuration("billing.cleanup_interval"))

	// API key self-service rotation — depends only on the database, so it
	// works whether or not Stripe billing is configured.
	keyRotationSvc := billing.NewKeyRotationService(
		billingRepo,
		cfg.GetDuration("auth.rotation_grace"),
		cachedRepo,
	)

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

	// GeoIP reader — always created so lookups degrade gracefully and the admin
	// refresh endpoint has something to reload into. Databases are opened from
	// disk when present and downloaded in the background when not.
	geoReader := initGeoIP(ctx, cfg, logger, status)
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
	ipService := service.NewIPService(redisCache, defaultCacheTTL, cacheTTLs, cfg.GetDuration("ip.lookup_timeout"), geoReader, alerter, ipTIProviders)

	// HTTP
	h := handler.New(handler.Deps{
		DomainService:      domainService,
		IPService:          ipService,
		FingerprintService: fpService,
		BillingService:     billingSvc,
		UsageService:       usageQuerySvc,
		KeyRotationService: keyRotationSvc,
		GeoRefresher:       geoReader,
		Config:             cfg,
		RedisCache:         redisCache,
		AuthCacheStats:     cachedRepo,
		DB:                 db,
		Status:             status,
	})
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
