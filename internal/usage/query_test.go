package usage

import (
	"database/sql/driver"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// --- buildWhere tests ---

func TestBuildWhere_NoFilters(t *testing.T) {
	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	where, args := buildWhere(0, 0, since, until)

	want := "WHERE created_at >= $1 AND created_at < $2"
	if where != want {
		t.Errorf("where clause:\n got  %q\n want %q", where, want)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
	if args[0] != since {
		t.Errorf("args[0] = %v, want %v", args[0], since)
	}
	if args[1] != until {
		t.Errorf("args[1] = %v, want %v", args[1], until)
	}
}

func TestBuildWhere_CustomerIDOnly(t *testing.T) {
	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	where, args := buildWhere(42, 0, since, until)

	want := "WHERE created_at >= $1 AND created_at < $2 AND customer_id = $3"
	if where != want {
		t.Errorf("where clause:\n got  %q\n want %q", where, want)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(args))
	}
	if args[2] != 42 {
		t.Errorf("args[2] = %v, want 42", args[2])
	}
}

func TestBuildWhere_BothFilters(t *testing.T) {
	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	where, args := buildWhere(42, 7, since, until)

	want := "WHERE created_at >= $1 AND created_at < $2 AND customer_id = $3 AND api_key_id = $4"
	if where != want {
		t.Errorf("where clause:\n got  %q\n want %q", where, want)
	}
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d", len(args))
	}
	if args[2] != 42 {
		t.Errorf("args[2] = %v, want 42", args[2])
	}
	if args[3] != 7 {
		t.Errorf("args[3] = %v, want 7", args[3])
	}
}

// --- QueryUsage tests ---

func aggColumns() []string {
	cols := []string{"total_requests", "cache_hits", "cache_misses", "avg_latency", "total_domains", "total_ips"}
	return append(cols, LookupColumns...)
}

// aggRow builds an aggregate row: the six fixed metrics followed by one count
// per lookup column, defaulting to 0 for anything absent from features.
func aggRow(totalRequests, cacheHits, cacheMisses int, avgLatency float64, totalDomains, totalIPs int, features map[string]int) []driver.Value {
	row := []driver.Value{totalRequests, cacheHits, cacheMisses, avgLatency, totalDomains, totalIPs}
	for _, name := range LookupColumns {
		row = append(row, features[name])
	}
	return row
}

var happyPathFeatures = map[string]int{
	"whois": 40, "dns": 60, "ssl": 30, "headers": 22,
	"screenshot": 10, "reputation": 20, "email_security": 15,
	"subdomains": 12, "ct_logs": 8, "bgp": 5,
	"fingerprint": 25, "threat_intel": 3,
}

func TestQueryUsage_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	// Aggregate query
	mock.ExpectQuery("SELECT").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows(aggColumns()).
			AddRow(aggRow(100, 30, 70, 45.678, 80, 15, happyPathFeatures)...))

	// Status code query
	mock.ExpectQuery("SELECT status_code").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "count"}).
			AddRow(200, 85).
			AddRow(429, 10).
			AddRow(500, 5))

	// Path query
	mock.ExpectQuery("SELECT path").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"path", "count"}).
			AddRow("/v1/domain/lookup", 90).
			AddRow("/v1/hello", 10))

	qs := NewQueryService(db)
	summary, err := qs.QueryUsage(0, 0, since, until)
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}

	if summary.TotalRequests != 100 {
		t.Errorf("TotalRequests = %d, want 100", summary.TotalRequests)
	}
	if summary.CacheHits != 30 {
		t.Errorf("CacheHits = %d, want 30", summary.CacheHits)
	}
	if summary.CacheHitRate != 30.0 {
		t.Errorf("CacheHitRate = %f, want 30.0", summary.CacheHitRate)
	}
	if summary.AvgLatencyMs != 45.67 {
		t.Errorf("AvgLatencyMs = %f, want 45.67", summary.AvgLatencyMs)
	}
	if summary.TotalDomains != 80 {
		t.Errorf("TotalDomains = %d, want 80", summary.TotalDomains)
	}
	if summary.TotalIPs != 15 {
		t.Errorf("TotalIPs = %d, want 15", summary.TotalIPs)
	}

	// Feature usage
	features := map[string]int{
		"screenshot": 10, "reputation": 20, "email_security": 15,
		"subdomains": 12, "ct_logs": 8, "bgp": 5,
		"fingerprint": 25, "threat_intel": 3,
	}
	for k, want := range features {
		if got := summary.FeatureUsage[k]; got != want {
			t.Errorf("FeatureUsage[%q] = %d, want %d", k, got, want)
		}
	}

	// Status codes
	if summary.StatusCodes["200"] != 85 {
		t.Errorf("StatusCodes[200] = %d, want 85", summary.StatusCodes["200"])
	}
	if summary.StatusCodes["429"] != 10 {
		t.Errorf("StatusCodes[429] = %d, want 10", summary.StatusCodes["429"])
	}
	if summary.StatusCodes["500"] != 5 {
		t.Errorf("StatusCodes[500] = %d, want 5", summary.StatusCodes["500"])
	}

	// Paths
	if summary.RequestsByPath["/v1/domain/lookup"] != 90 {
		t.Errorf("RequestsByPath[/v1/domain/lookup] = %d, want 90", summary.RequestsByPath["/v1/domain/lookup"])
	}
	if summary.RequestsByPath["/v1/hello"] != 10 {
		t.Errorf("RequestsByPath[/v1/hello] = %d, want 10", summary.RequestsByPath["/v1/hello"])
	}

	// Period
	if !summary.PeriodStart.Equal(since) {
		t.Errorf("PeriodStart = %v, want %v", summary.PeriodStart, since)
	}
	if !summary.PeriodEnd.Equal(until) {
		t.Errorf("PeriodEnd = %v, want %v", summary.PeriodEnd, until)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestQueryUsage_NoData(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	// Aggregate: all zeros
	mock.ExpectQuery("SELECT").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows(aggColumns()).
			AddRow(aggRow(0, 0, 0, 0.0, 0, 0, nil)...))

	// Status codes: no rows
	mock.ExpectQuery("SELECT status_code").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "count"}))

	// Paths: no rows
	mock.ExpectQuery("SELECT path").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"path", "count"}))

	qs := NewQueryService(db)
	summary, err := qs.QueryUsage(0, 0, since, until)
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}

	if summary.TotalRequests != 0 {
		t.Errorf("TotalRequests = %d, want 0", summary.TotalRequests)
	}
	if summary.CacheHitRate != 0 {
		t.Errorf("CacheHitRate = %f, want 0", summary.CacheHitRate)
	}
	if summary.AvgLatencyMs != 0 {
		t.Errorf("AvgLatencyMs = %f, want 0", summary.AvgLatencyMs)
	}

	// Maps should be initialized (not nil), even with no data.
	if summary.StatusCodes == nil {
		t.Error("StatusCodes is nil, want initialized map")
	}
	if summary.FeatureUsage == nil {
		t.Error("FeatureUsage is nil, want initialized map")
	}
	if summary.RequestsByPath == nil {
		t.Error("RequestsByPath is nil, want initialized map")
	}
	if len(summary.StatusCodes) != 0 {
		t.Errorf("StatusCodes has %d entries, want 0", len(summary.StatusCodes))
	}
	if len(summary.RequestsByPath) != 0 {
		t.Errorf("RequestsByPath has %d entries, want 0", len(summary.RequestsByPath))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestQueryUsage_AggregateQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	mock.ExpectQuery("SELECT").
		WithArgs(since, until).
		WillReturnError(fmt.Errorf("connection refused"))

	qs := NewQueryService(db)
	_, err = qs.QueryUsage(0, 0, since, until)
	if err == nil {
		t.Fatal("expected error from aggregate query failure")
	}
	wantMsg := "query usage aggregates"
	if got := err.Error(); !containsSubstr(got, wantMsg) {
		t.Errorf("error = %q, want it to contain %q", got, wantMsg)
	}
}

func TestQueryUsage_StatusCodeQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	// Aggregate succeeds
	mock.ExpectQuery("SELECT").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows(aggColumns()).
			AddRow(aggRow(10, 3, 7, 12.5, 8, 0, nil)...))

	// Status code query fails
	mock.ExpectQuery("SELECT status_code").
		WithArgs(since, until).
		WillReturnError(fmt.Errorf("table dropped"))

	qs := NewQueryService(db)
	_, err = qs.QueryUsage(0, 0, since, until)
	if err == nil {
		t.Fatal("expected error from status code query failure")
	}
	wantMsg := "query status codes"
	if got := err.Error(); !containsSubstr(got, wantMsg) {
		t.Errorf("error = %q, want it to contain %q", got, wantMsg)
	}
}

func TestQueryUsage_PathQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	// Aggregate succeeds
	mock.ExpectQuery("SELECT").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows(aggColumns()).
			AddRow(aggRow(10, 3, 7, 12.5, 8, 0, nil)...))

	// Status code query succeeds
	mock.ExpectQuery("SELECT status_code").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "count"}).
			AddRow(200, 10))

	// Path query fails
	mock.ExpectQuery("SELECT path").
		WithArgs(since, until).
		WillReturnError(fmt.Errorf("disk full"))

	qs := NewQueryService(db)
	_, err = qs.QueryUsage(0, 0, since, until)
	if err == nil {
		t.Fatal("expected error from path query failure")
	}
	wantMsg := "query paths"
	if got := err.Error(); !containsSubstr(got, wantMsg) {
		t.Errorf("error = %q, want it to contain %q", got, wantMsg)
	}
}

func TestQueryUsage_WithCustomerFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	// Expect 3 args: since, until, customerID=42
	mock.ExpectQuery("SELECT").
		WithArgs(since, until, 42).
		WillReturnRows(sqlmock.NewRows(aggColumns()).
			AddRow(aggRow(5, 2, 8, 20.0, 4, 0, map[string]int{"screenshot": 1})...))

	mock.ExpectQuery("SELECT status_code").
		WithArgs(since, until, 42).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "count"}).
			AddRow(200, 5))

	mock.ExpectQuery("SELECT path").
		WithArgs(since, until, 42).
		WillReturnRows(sqlmock.NewRows([]string{"path", "count"}).
			AddRow("/v1/domain/lookup", 5))

	qs := NewQueryService(db)
	summary, err := qs.QueryUsage(42, 0, since, until)
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}

	if summary.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", summary.TotalRequests)
	}
	if summary.FeatureUsage["screenshot"] != 1 {
		t.Errorf("FeatureUsage[screenshot] = %d, want 1", summary.FeatureUsage["screenshot"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestQueryUsage_CacheHitRateCalculation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	// 3 cache hits out of 10 requests = 30.0%
	mock.ExpectQuery("SELECT").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows(aggColumns()).
			AddRow(aggRow(10, 3, 7, 50.0, 10, 0, nil)...))

	mock.ExpectQuery("SELECT status_code").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "count"}))

	mock.ExpectQuery("SELECT path").
		WithArgs(since, until).
		WillReturnRows(sqlmock.NewRows([]string{"path", "count"}))

	qs := NewQueryService(db)
	summary, err := qs.QueryUsage(0, 0, since, until)
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}

	if summary.CacheHitRate != 30.0 {
		t.Errorf("CacheHitRate = %f, want 30.0 (3 hits / 10 requests)", summary.CacheHitRate)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// containsSubstr is a small helper to check substring containment.
func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && searchSubstr(s, sub)
}

func searchSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
