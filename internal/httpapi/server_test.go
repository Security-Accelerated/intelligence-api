package httpapi

import (
	"net/http"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func testLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	return zap.New(core), logs
}

func TestServe_ShutdownOnSignal(t *testing.T) {
	logger, _ := testLogger()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server := NewServer(mux, 0) // port 0 = pick a free port

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	cancelled := false

	go func() {
		done <- Serve(server, sigCh, func() { cancelled = true }, logger)
	}()

	// Give the server time to start
	time.Sleep(50 * time.Millisecond)

	// Send shutdown signal
	sigCh <- os.Interrupt

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within timeout")
	}

	if !cancelled {
		t.Error("appCancel was not called")
	}
}

func TestServe_ServerListenError(t *testing.T) {
	logger, _ := testLogger()

	// Bind to an invalid address to force a listen error
	server := &http.Server{
		Addr:    ":-1",
		Handler: http.NewServeMux(),
	}

	sigCh := make(chan os.Signal, 1)

	err := Serve(server, sigCh, func() {}, logger)
	if err == nil {
		t.Fatal("expected error from Serve, got nil")
	}
}
