package auth

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

// minBufferSize is the minimum allowed buffer size to prevent misconfiguration
// from silently dropping most touches and causing false stale-account deactivations.
const minBufferSize = 64

// LastUsedBatcher collects API key IDs and batch-updates their last_used_at
// timestamps on a timer. This replaces per-request fire-and-forget goroutines
// with a single background worker that respects graceful shutdown.
type LastUsedBatcher struct {
	db            *sql.DB
	ch            chan int
	flushInterval time.Duration
	logger        *zap.Logger
	wg            sync.WaitGroup
	stopCh        chan struct{}
	dropped       atomic.Int64
}

// NewLastUsedBatcher creates and starts a batcher that flushes accumulated key
// IDs to the database every flushInterval. bufferSize controls the channel
// capacity; it is clamped to a minimum of 64 to prevent misconfiguration.
func NewLastUsedBatcher(db *sql.DB, bufferSize int, flushInterval time.Duration, logger *zap.Logger) *LastUsedBatcher {
	if bufferSize < minBufferSize {
		logger.Warn("auth.last_used_buffer_size too small, clamping to minimum",
			zap.Int("configured", bufferSize),
			zap.Int("minimum", minBufferSize),
		)
		bufferSize = minBufferSize
	}
	b := &LastUsedBatcher{
		db:            db,
		ch:            make(chan int, bufferSize),
		flushInterval: flushInterval,
		logger:        logger,
		stopCh:        make(chan struct{}),
	}
	b.wg.Add(1)
	go b.run()
	return b
}

// Touch enqueues an API key ID for a batched last_used_at update.
// Non-blocking: logs a warning and increments a drop counter if the channel is full.
func (b *LastUsedBatcher) Touch(apiKeyID int) {
	select {
	case b.ch <- apiKeyID:
	default:
		total := b.dropped.Add(1)
		b.logger.Warn("last_used_at touch dropped (buffer full), risk of false stale-account deactivation",
			zap.Int("api_key_id", apiKeyID),
			zap.Int64("total_dropped", total),
		)
	}
}

// Stop drains remaining entries and waits for the background goroutine to exit.
func (b *LastUsedBatcher) Stop() {
	close(b.stopCh)
	b.wg.Wait()
}

func (b *LastUsedBatcher) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	seen := make(map[int]struct{})

	for {
		select {
		case id := <-b.ch:
			seen[id] = struct{}{}
		case <-ticker.C:
			if len(seen) > 0 {
				b.flush(seen)
				seen = make(map[int]struct{})
			}
		case <-b.stopCh:
			// Drain remaining entries from channel.
			for {
				select {
				case id := <-b.ch:
					seen[id] = struct{}{}
				default:
					if len(seen) > 0 {
						b.flush(seen)
					}
					return
				}
			}
		}
	}
}

func (b *LastUsedBatcher) flush(ids map[int]struct{}) {
	if len(ids) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build UPDATE ... WHERE id = ANY($1)
	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	i := 1
	for id := range ids {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		args = append(args, id)
		i++
	}

	query := fmt.Sprintf(
		`UPDATE api_keys SET last_used_at = now() WHERE id IN (%s)`,
		strings.Join(placeholders, ","),
	)

	if _, err := b.db.ExecContext(ctx, query, args...); err != nil {
		b.logger.Error("failed to flush last_used_at batch", zap.Error(err), zap.Int("count", len(ids)))
	}
}
