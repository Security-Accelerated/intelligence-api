package httpapi

import (
	"context"
	"fmt"
	"net/http"
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

// Serve starts the server and blocks until shutdown is signalled. It returns
// nil on clean shutdown.
func Serve(server *http.Server, shutdown <-chan struct{}, logger *zap.Logger) error {
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server started", zap.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case <-shutdown:
		logger.Info("shutdown signal received")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed, forcing close", zap.Error(err))
		server.Close()
	}

	return nil
}
