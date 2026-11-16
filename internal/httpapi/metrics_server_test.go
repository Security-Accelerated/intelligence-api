package httpapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/security-accelerated/intelligence-api/internal/metrics/metricstest"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/usage"
	"go.uber.org/zap"
)

func newTestMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	m, err := metrics.New("v1.2.3")
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}
	return m
}

func testMetricsServerConfig(addr string) MetricsServerConfig {
	return MetricsServerConfig{
		Addr:         addr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Second,
	}
}

// freeAddr returns a loopback address nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

func get(t *testing.T, url string) (status int, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(b)
}

func TestStartMetricsServer_ServesOnlyMetrics(t *testing.T) {
	addr := freeAddr(t)
	stop, err := StartMetricsServer(t.Context(), testMetricsServerConfig(addr), newTestMetrics(t).Handler(), zap.NewNop())
	if err != nil {
		t.Fatalf("StartMetricsServer: %v", err)
	}

	status, body := get(t, "http://"+addr+"/metrics")
	if status != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", status)
	}
	if !strings.Contains(body, `intelligence_api_build_info{goversion="`) || !strings.Contains(body, `version="v1.2.3"`) {
		t.Errorf("GET /metrics did not return the build info series:\n%.400s", body)
	}

	// The listener carries the one path. Nothing of the API is reachable on it.
	for _, path := range []string{"/", "/v1/health", "/v1/info", "/metrics/x"} {
		if status, _ := get(t, "http://"+addr+path); status != http.StatusNotFound {
			t.Errorf("GET %s on the metrics listener = %d, want 404", path, status)
		}
	}

	if err := stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/metrics", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Error("the listener still answers after stop")
	}
}

// A port that cannot be bound has to fail startup, not leave the process
// running with metrics silently absent.
func TestStartMetricsServer_BindFailureIsReturned(t *testing.T) {
	var lc net.ListenConfig
	taken, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer taken.Close()

	stop, err := StartMetricsServer(t.Context(), testMetricsServerConfig(taken.Addr().String()), http.NotFoundHandler(), zap.NewNop())
	if err == nil {
		_ = stop(context.Background())
		t.Fatal("StartMetricsServer on a taken port returned nil, want an error")
	}
}

// The public router must not serve /metrics: the endpoint is unauthenticated,
// and its own listener is the only thing standing between it and the internet.
func TestNewRouter_DoesNotServeMetricsAndRecordsTheAttempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMetrics(t)
	// The Redis client is never dialed: nothing here reaches the rate limiter.
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	t.Cleanup(func() { _ = client.Close() })

	router := NewRouter(handler.New(handler.Deps{}), auth.NewCachedRepository(nil, time.Minute), client,
		middleware.RateLimitConfig{}, usage.NoopRecorder{}, "test", 1<<20, m)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics on the public router = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "intelligence_api_") {
		t.Error("the public router's 404 body contains metric names")
	}

	// The request itself went through the metrics middleware like any other.
	metricstest.Want(t, m,
		`intelligence_api_http_request_duration_seconds_count{method="GET",plan="none",route="unmatched",status="404"}`, 1)
}
