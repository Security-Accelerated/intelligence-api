package usage

import (
	"context"
	"database/sql"
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

	// Use a transaction with a prepared statement for the batch. This keeps all
	// inserts on one connection with a single prepared statement, avoiding the
	// "unnamed prepared statement does not exist" error on serverless Postgres
	// (Neon) where the pooler can invalidate prepared statements across calls.
	tx, err := ul.db.BeginTx(ctx, nil)
	if err != nil {
		ul.logger.Error("failed to begin usage flush tx", zap.Error(err), zap.Int("count", len(entries)))
		return
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO request_log
		(customer_id, api_key_id, plan, method, path, status_code, latency_ms,
		 domain_count, ip_count, cache_hit, screenshot, reputation, email_security,
		 subdomains, ct_logs, bgp, fingerprint, threat_intel, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`)
	if err != nil {
		tx.Rollback()
		ul.logger.Error("failed to prepare usage flush stmt", zap.Error(err), zap.Int("count", len(entries)))
		return
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx,
			nilIfZero(e.CustomerID), nilIfZero(e.APIKeyID), nilIfEmpty(e.Plan),
			e.Method, e.Path, e.StatusCode, e.LatencyMs, e.DomainCount, e.IPCount,
			e.CacheHit, e.Screenshot, e.Reputation, e.EmailSecurity,
			e.Subdomains, e.CTLogs, e.BGP, e.Fingerprint, e.ThreatIntel,
			now,
		); err != nil {
			tx.Rollback()
			ul.logger.Error("failed to flush usage entry", zap.Error(err), zap.Int("count", len(entries)))
			return
		}
	}

	if err := tx.Commit(); err != nil {
		ul.logger.Error("failed to commit usage flush", zap.Error(err), zap.Int("count", len(entries)))
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
