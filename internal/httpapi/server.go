package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// ServerConfig holds configurable HTTP server parameters.
type ServerConfig struct {
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// NewServer creates an http.Server with the given configuration.
func NewServer(handler http.Handler, cfg ServerConfig) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
}

// Serve starts the server and blocks until a signal is received or a fatal
// server error occurs. It calls appCancel to tear down app-level resources,
// then gracefully drains in-flight requests. A second signal forces immediate
// shutdown. Returns nil on clean shutdown.
func Serve(server *http.Server, sigCh <-chan os.Signal, appCancel context.CancelFunc, logger *zap.Logger, shutdownTimeout time.Duration) error {
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server started", zap.String("addr", server.Addr))
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		appCancel()
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	}

	appCancel()

	// Force close on second signal
	shutdownDone := make(chan struct{})
	go func() {
		select {
		case sig := <-sigCh:
			logger.Warn("second signal received, forcing close", zap.String("signal", sig.String()))
			if err := server.Close(); err != nil {
				logger.Error("server close failed", zap.Error(err))
			}
		case <-shutdownDone:
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed, forcing close", zap.Error(err))
		if err := server.Close(); err != nil {
			logger.Error("server close failed", zap.Error(err))
		}
	}
	close(shutdownDone)

	return nil
}
