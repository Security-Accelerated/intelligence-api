package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// MetricsServerConfig configures the listener that serves /metrics.
type MetricsServerConfig struct {
	// Addr is the listen address, e.g. ":9091".
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// StartMetricsServer serves handler at GET /metrics on a listener of its own,
// apart from the API's port, and returns once that listener is bound.
//
// The separate listener is the access control: nothing routes the public port
// here, so the endpoint needs no credential a scraper would have to hold. See
// docs/decisions.md.
//
// A bind failure is returned, so a deployment that asks for metrics and cannot
// serve them fails at startup instead of running without them. A failure after
// that is logged and leaves the API serving. The caller owns the server's
// lifetime and must call the returned stop function, which waits for an
// in-flight scrape until ctx ends.
func StartMetricsServer(ctx context.Context, cfg MetricsServerConfig, handler http.Handler, logger *zap.Logger) (stop func(context.Context) error, err error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", cfg.Addr, err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", handler)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	go func() {
		logger.Info("metrics server started", zap.String("addr", ln.Addr().String()))
		if err := server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server stopped", zap.Error(err))
		}
	}()

	return server.Shutdown, nil
}
