package app

import (
	"context"
	"fmt"

	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/httpapi"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// startMetricsServer starts the Prometheus listener when metrics.enabled is
// set and returns the function that stops it. With metrics disabled it starts
// nothing and returns a no-op, so the caller defers the result either way.
//
// The listener shares the API server's timeouts: it is the same process
// answering the same kind of short request, and a second set of keys would be
// three more values nobody has a reason to set differently.
func startMetricsServer(ctx context.Context, cfg *viper.Viper, m *metrics.Metrics, serverCfg httpapi.ServerConfig, logger *zap.Logger, status *config.StatusSnapshot) (stop func(), err error) {
	if !cfg.GetBool("metrics.enabled") {
		logger.Info("metrics endpoint disabled (metrics.enabled is false)")
		return func() {}, nil
	}

	addr := cfg.GetString("metrics.listen_addr")
	shutdown, err := httpapi.StartMetricsServer(ctx, httpapi.MetricsServerConfig{
		Addr:         addr,
		ReadTimeout:  serverCfg.ReadTimeout,
		WriteTimeout: serverCfg.WriteTimeout,
		IdleTimeout:  serverCfg.IdleTimeout,
	}, m.Handler(), logger)
	if err != nil {
		return nil, fmt.Errorf("start metrics server: %w", err)
	}

	status.Services.Metrics = config.MetricsStatus{Enabled: true, ListenAddr: addr}
	logger.Info("metrics endpoint enabled", zap.Any("config", status.Services.Metrics))

	return func() {
		// Run's own context is already canceled by the time this runs, so the
		// drain gets a fresh one bounded by the same shutdown timeout.
		stopCtx, cancel := context.WithTimeout(context.Background(), serverCfg.ShutdownTimeout)
		defer cancel()
		if err := shutdown(stopCtx); err != nil {
			logger.Error("metrics server shutdown failed", zap.Error(err))
		}
	}, nil
}
