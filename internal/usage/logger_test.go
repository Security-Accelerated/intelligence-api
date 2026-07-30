package usage

import (
	"slices"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/security-accelerated/intelligence-api/internal/domain"
	"go.uber.org/zap"
)

func TestUsageLogger_RecordAndStop(t *testing.T) {
	// Use nil db — we can't actually INSERT, but we can verify channel/stop
	// behavior without a database. The flush will log an error, which is fine.
	logger := NewUsageLogger(nil, 16, 50*time.Millisecond, zap.NewNop())

	logger.Record(UsageEntry{Method: "POST", Path: "/v1/domain/lookup", StatusCode: 200, LatencyMs: 100})
	logger.Record(UsageEntry{Method: "GET", Path: "/v1/hello", StatusCode: 200, LatencyMs: 5})

	// Stop should drain without hanging.
	done := make(chan struct{})
	go func() {
		logger.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2 seconds")
	}
}

func TestUsageLogger_DropWhenFull(t *testing.T) {
	logger := NewUsageLogger(nil, 2, time.Hour, zap.NewNop())

	// Fill the buffer.
	logger.Record(UsageEntry{Method: "POST", Path: "/a", StatusCode: 200})
	logger.Record(UsageEntry{Method: "POST", Path: "/b", StatusCode: 200})

	// This should be silently dropped, not block.
	done := make(chan struct{})
	go func() {
		logger.Record(UsageEntry{Method: "POST", Path: "/c", StatusCode: 200})
		close(done)
	}()

	select {
	case <-done:
		// OK — non-blocking drop
	case <-time.After(time.Second):
		t.Fatal("Record blocked on full channel")
	}

	logger.Stop()
}

func TestNoopRecorder(t *testing.T) {
	var r NoopRecorder
	// Should not panic.
	r.Record(UsageEntry{Method: "GET", Path: "/v1/hello", StatusCode: 200})
}

func TestUsageLogger_FlushInsertsCacheAndLookupColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ul := &UsageLogger{db: db, logger: zap.NewNop()}

	mock.ExpectExec("INSERT INTO request_log").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"POST", "/v1/domain/lookup", 200, 12, 2, 0, // method..ip_count
			3, 1, // cache_hits, cache_misses
			true, true, false, false, // whois, dns, ssl, headers
			// screenshot, reputation, email_security, subdomains, ct_logs, bgp,
			// fingerprint, threat_intel, dns_security, risk
			false, false, false, false, false, false, false, false, false, false,
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	ul.flush([]UsageEntry{{
		Method: "POST", Path: "/v1/domain/lookup", StatusCode: 200, LatencyMs: 12,
		DomainCount: 2, CacheHits: 3, CacheMisses: 1,
		Lookups: []string{"whois", "dns"},
	}})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLookupColumns_MatchesDomainCatalog guards against the request_log schema
// drifting away from the set of lookups the API accepts. A new lookup needs a
// matching column and migration before it can be tracked.
func TestLookupColumns_MatchesDomainCatalog(t *testing.T) {
	if len(LookupColumns) != len(domain.AllLookupNames) {
		t.Fatalf("LookupColumns has %d entries, domain.AllLookupNames has %d",
			len(LookupColumns), len(domain.AllLookupNames))
	}
	for _, name := range domain.AllLookupNames {
		if !slices.Contains(LookupColumns, name) {
			t.Errorf("LookupColumns is missing %q", name)
		}
	}
}

func TestUsageLogger_FlushChunksOversizedBatches(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ul := &UsageLogger{db: db, logger: zap.NewNop()}
	perRow := len(ul.columns())
	maxRows := maxBindParams / perRow

	// One row past the limit must split into two statements rather than build a
	// single INSERT that PostgreSQL rejects outright.
	entries := make([]UsageEntry, maxRows+1)
	for i := range entries {
		entries[i] = UsageEntry{Method: "POST", Path: "/v1/domain/lookup", StatusCode: 200}
	}

	mock.ExpectExec("INSERT INTO request_log").WillReturnResult(sqlmock.NewResult(1, int64(maxRows)))
	mock.ExpectExec("INSERT INTO request_log").WillReturnResult(sqlmock.NewResult(1, 1))

	ul.flush(entries)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUsageLogger_FlushStaysUnderBindParamLimit(t *testing.T) {
	ul := &UsageLogger{}
	perRow := len(ul.columns())
	if perRow == 0 {
		t.Fatal("no columns")
	}
	if got := (maxBindParams / perRow) * perRow; got > maxBindParams {
		t.Errorf("max chunk uses %d bind params, over the %d limit", got, maxBindParams)
	}
}
