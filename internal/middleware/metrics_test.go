package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
	"github.com/security-accelerated/intelligence-api/internal/metrics/metricstest"
)

func newTestMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	m, err := metrics.New("test")
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}
	return m
}

// metricsRouter mirrors the production order: Metrics first, then Recovery.
func metricsRouter(m *metrics.Metrics) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Metrics(m))
	r.Use(gin.Recovery())
	r.GET("/v1/things/:id", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/v1/authed", func(c *gin.Context) {
		c.Set("api_key_plan", "pro")
		c.Status(http.StatusOK)
	})
	r.GET("/v1/boom", func(*gin.Context) { panic("boom") })
	return r
}

func serve(r *gin.Engine, method, path string) int {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, http.NoBody))
	return w.Code
}

const httpCount = "intelligence_api_http_request_duration_seconds_count"

func TestMetrics_LabelsByRouteTemplateMethodStatusAndPlan(t *testing.T) {
	m := newTestMetrics(t)
	r := metricsRouter(m)

	serve(r, http.MethodGet, "/v1/things/1")
	serve(r, http.MethodGet, "/v1/things/2")
	serve(r, http.MethodGet, "/v1/authed")

	// Two different paths, one route: the label is the template.
	metricstest.Want(t, m, httpCount+`{method="GET",plan="none",route="/v1/things/:id",status="200"}`, 2)
	metricstest.Want(t, m, httpCount+`{method="GET",plan="pro",route="/v1/authed",status="200"}`, 1)
}

// Paths and methods are chosen by the caller. Neither may become a label
// value as sent, or a scanner walking /a, /b, /c mints a series per request.
func TestMetrics_CallerChosenValuesAreBounded(t *testing.T) {
	m := newTestMetrics(t)
	r := metricsRouter(m)

	serve(r, http.MethodGet, "/nope/1")
	serve(r, http.MethodGet, "/nope/2")
	serve(r, "PROPFIND", "/nope/3")
	serve(r, "MADEUP", "/nope/4")

	metricstest.Want(t, m, httpCount+`{method="GET",plan="none",route="unmatched",status="404"}`, 2)
	metricstest.Want(t, m, httpCount+`{method="other",plan="none",route="unmatched",status="404"}`, 2)
}

// The reason Metrics sits ahead of Recovery in the chain.
func TestMetrics_PanicIsRecordedAs500(t *testing.T) {
	m := newTestMetrics(t)
	r := metricsRouter(m)

	if code := serve(r, http.MethodGet, "/v1/boom"); code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}

	metricstest.Want(t, m, httpCount+`{method="GET",plan="none",route="/v1/boom",status="500"}`, 1)
}

func TestRateLimit_CountsRejectionsByPlan(t *testing.T) {
	m := newTestMetrics(t)
	r, _, _ := setupRateLimit(t, RateLimitConfig{Free: 2, Pro: 10, Metrics: m})

	const rejections = `intelligence_api_rate_limit_rejections_total{plan="free"}`

	// Allowed requests are not rejections. The series already exists at zero,
	// so the first rejection is an increase rate() can see.
	doRequest(r)
	doRequest(r)
	metricstest.Want(t, m, rejections, 0)
	metricstest.Want(t, m, `intelligence_api_rate_limit_rejections_total{plan="pro"}`, 0)

	for range 3 {
		if w := doRequest(r); w.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", w.Code)
		}
	}
	metricstest.Want(t, m, rejections, 3)
}

func TestMetrics_NilRecordsNothing(t *testing.T) {
	r := metricsRouter(nil)
	if code := serve(r, http.MethodGet, "/v1/things/1"); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
}
