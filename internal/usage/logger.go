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

	// Fixed metadata columns, followed by one boolean column per lookup, then
	// created_at. LookupColumns must match the request_log schema.
	baseColumns := []string{
		"customer_id", "api_key_id", "plan", "method", "path", "status_code",
		"latency_ms", "domain_count", "ip_count", "cache_hits", "cache_misses",
	}
	columns := append(append(append([]string{}, baseColumns...), LookupColumns...), "created_at")
	cols := len(columns)

	// Build a multi-row INSERT for efficiency.
	valueStrings := make([]string, 0, len(entries))
	args := make([]any, 0, len(entries)*cols)
	placeholders := make([]string, cols)

	now := time.Now().UTC()
	for i, e := range entries {
		base := i * cols
		for j := range placeholders {
			placeholders[j] = fmt.Sprintf("$%d", base+j+1)
		}
		valueStrings = append(valueStrings, "("+strings.Join(placeholders, ",")+")")

		args = append(args,
			nilIfZero(e.CustomerID), nilIfZero(e.APIKeyID), nilIfEmpty(e.Plan),
			e.Method, e.Path, e.StatusCode, e.LatencyMs, e.DomainCount, e.IPCount,
			e.CacheHits, e.CacheMisses,
		)
		requested := make(map[string]bool, len(e.Lookups))
		for _, name := range e.Lookups {
			requested[name] = true
		}
		for _, name := range LookupColumns {
			args = append(args, requested[name])
		}
		args = append(args, now)
	}

	query := fmt.Sprintf(`INSERT INTO request_log (%s) VALUES %s`,
		strings.Join(columns, ", "), strings.Join(valueStrings, ","))

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
