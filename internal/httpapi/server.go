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

// NewServer creates an http.Server with production-ready timeouts.
func NewServer(handler http.Handler, port int) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Serve starts the server and blocks until a signal is received or a fatal
// server error occurs. It calls appCancel to tear down app-level resources,
// then gracefully drains in-flight requests. A second signal forces immediate
// shutdown. Returns nil on clean shutdown.
func Serve(server *http.Server, sigCh <-chan os.Signal, appCancel context.CancelFunc, logger *zap.Logger) error {
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
