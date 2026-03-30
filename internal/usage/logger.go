package usage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// UsageLogger buffers UsageEntry values and batch-inserts them into PostgreSQL.
type UsageLogger struct {
	db            *sql.DB
	ch            chan UsageEntry
	flushInterval time.Duration
	logger        *zap.Logger
	wg            sync.WaitGroup
	stopCh        chan struct{}
	dropped       atomic.Int64
}

// NewUsageLogger creates a UsageLogger that flushes to db on a timer or when
// the buffer reaches batchThreshold entries. bufferSize controls the channel
// capacity; entries are silently dropped (with a warning log) when full.
func NewUsageLogger(db *sql.DB, bufferSize int, flushInterval time.Duration, logger *zap.Logger) *UsageLogger {
	ul := &UsageLogger{
		db:            db,
		ch:            make(chan UsageEntry, bufferSize),
		flushInterval: flushInterval,
		logger:        logger,
		stopCh:        make(chan struct{}),
	}
	ul.wg.Add(1)
	go ul.run()
	return ul
}

// Record enqueues an entry for batch insertion. Non-blocking: drops if the
// channel is full and increments the dropped counter.
func (ul *UsageLogger) Record(entry UsageEntry) {
	select {
	case ul.ch <- entry:
	default:
		ul.dropped.Add(1)
		ul.logger.Warn("usage log buffer full, dropping entry",
			zap.Int64("total_dropped", ul.dropped.Load()),
		)
	}
}

// Stop drains remaining entries and waits for the background goroutine to exit.
func (ul *UsageLogger) Stop() {
	close(ul.stopCh)
	ul.wg.Wait()
}

func (ul *UsageLogger) run() {
	defer ul.wg.Done()
	ticker := time.NewTicker(ul.flushInterval)
	defer ticker.Stop()

	var buf []UsageEntry
	const batchThreshold = 50

	for {
		select {
		case entry := <-ul.ch:
			buf = append(buf, entry)
			if len(buf) >= batchThreshold {
				ul.flush(buf)
				buf = nil
			}
		case <-ticker.C:
			if len(buf) > 0 {
				ul.flush(buf)
				buf = nil
			}
		case <-ul.stopCh:
			// Drain remaining entries from channel.
			for {
				select {
				case entry := <-ul.ch:
					buf = append(buf, entry)
				default:
					if len(buf) > 0 {
						ul.flush(buf)
					}
					return
				}
			}
		}
	}
}

func (ul *UsageLogger) flush(entries []UsageEntry) {
	if len(entries) == 0 || ul.db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build a multi-row INSERT.
	const cols = 19
	valueStrings := make([]string, 0, len(entries))
	args := make([]any, 0, len(entries)*cols)

	for i, e := range entries {
		base := i * cols
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9,
			base+10, base+11, base+12, base+13, base+14, base+15, base+16, base+17, base+18, base+19,
		))
		args = append(args,
			nilIfZero(e.CustomerID), nilIfZero(e.APIKeyID), nilIfEmpty(e.Plan),
			e.Method, e.Path, e.StatusCode, e.LatencyMs, e.DomainCount, e.IPCount,
			e.CacheHit, e.Screenshot, e.Reputation, e.EmailSecurity,
			e.Subdomains, e.CTLogs, e.BGP, e.Fingerprint, e.ThreatIntel,
			time.Now().UTC(),
		)
	}

	query := fmt.Sprintf(`INSERT INTO request_log
		(customer_id, api_key_id, plan, method, path, status_code, latency_ms,
		 domain_count, ip_count, cache_hit, screenshot, reputation, email_security,
		 subdomains, ct_logs, bgp, fingerprint, threat_intel, created_at)
		VALUES %s`, strings.Join(valueStrings, ","))

	if _, err := ul.db.ExecContext(ctx, query, args...); err != nil {
		ul.logger.Error("failed to flush usage entries", zap.Error(err), zap.Int("count", len(entries)))
	}
}

func nilIfZero(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
