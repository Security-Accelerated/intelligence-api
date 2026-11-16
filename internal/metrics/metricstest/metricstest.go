// Package metricstest reads a metrics.Metrics the way Prometheus does, so tests
// in any package can assert on what a scrape would actually return.
package metricstest

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/security-accelerated/intelligence-api/internal/metrics"
)

// Scrape returns the exposition text a scrape of m produces.
func Scrape(t testing.TB, m *metrics.Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", w.Code)
	}
	return w.Body.String()
}

// Value returns the sample for one series and whether the scrape contains it.
// series is the name and label set exactly as exposed, labels in alphabetical
// order: `intelligence_api_rate_limit_rejections_total{plan="free"}`.
func Value(t testing.TB, m *metrics.Metrics, series string) (float64, bool) {
	t.Helper()
	for line := range strings.SplitSeq(Scrape(t, m), "\n") {
		rest, ok := strings.CutPrefix(line, series+" ")
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(rest, 64)
		if err != nil {
			t.Fatalf("series %s has unparseable value %q: %v", series, rest, err)
		}
		return v, true
	}
	return 0, false
}

// Want fails the test unless series is present with exactly the value want.
func Want(t testing.TB, m *metrics.Metrics, series string, want float64) {
	t.Helper()
	got, ok := Value(t, m, series)
	if !ok {
		t.Errorf("series %s is absent, want %v", series, want)
		return
	}
	if got != want {
		t.Errorf("series %s = %v, want %v", series, got, want)
	}
}

// WantAbsent fails the test if the scrape contains series.
func WantAbsent(t testing.TB, m *metrics.Metrics, series string) {
	t.Helper()
	if got, ok := Value(t, m, series); ok {
		t.Errorf("series %s = %v, want it absent", series, got)
	}
}
