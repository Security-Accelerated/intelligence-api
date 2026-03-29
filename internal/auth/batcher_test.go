package auth

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

func TestLastUsedBatcher_FlushesOnTick(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE api_keys SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 2))

	b := NewLastUsedBatcher(db, 64, 50*time.Millisecond, zap.NewNop())

	b.Touch(1)
	b.Touch(2)
	b.Touch(1) // duplicate should be deduplicated

	// Wait for a tick to flush
	time.Sleep(150 * time.Millisecond)
	b.Stop()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestLastUsedBatcher_FlushesOnStop(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE api_keys SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Use a long flush interval so the only flush is on Stop
	b := NewLastUsedBatcher(db, 64, 1*time.Hour, zap.NewNop())

	b.Touch(42)

	// Give the goroutine a moment to read from the channel
	time.Sleep(10 * time.Millisecond)
	b.Stop()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestLastUsedBatcher_DropsWhenFull(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Minimum buffer (64), long flush interval — send many more than buffer to trigger drops
	b := NewLastUsedBatcher(db, minBufferSize, 1*time.Hour, zap.NewNop())

	for i := 0; i < 500; i++ {
		b.Touch(i)
	}

	// Expect at least one flush on stop (whatever made it into the channel)
	mock.ExpectExec("UPDATE api_keys SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	b.Stop()

	if b.dropped.Load() == 0 {
		t.Error("expected some touches to be dropped, but none were")
	}
}

func TestLastUsedBatcher_ClampsSmallBuffer(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	b := NewLastUsedBatcher(db, 2, 1*time.Hour, zap.NewNop())
	defer b.Stop()

	if cap(b.ch) != minBufferSize {
		t.Errorf("buffer capacity = %d, want %d (should be clamped)", cap(b.ch), minBufferSize)
	}
}

func TestLastUsedBatcher_ClampsZeroFlushInterval(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Zero duration would panic time.NewTicker — should be clamped
	b := NewLastUsedBatcher(db, 64, 0, zap.NewNop())
	defer b.Stop()

	if b.flushInterval != minFlushInterval {
		t.Errorf("flushInterval = %v, want %v (should be clamped)", b.flushInterval, minFlushInterval)
	}
}

func TestLastUsedBatcher_ClampsNegativeFlushInterval(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	b := NewLastUsedBatcher(db, 64, -5*time.Second, zap.NewNop())
	defer b.Stop()

	if b.flushInterval != minFlushInterval {
		t.Errorf("flushInterval = %v, want %v (should be clamped)", b.flushInterval, minFlushInterval)
	}
}

func TestLastUsedBatcher_NilDB_ReturnsNil(t *testing.T) {
	b := NewLastUsedBatcher(nil, 64, 10*time.Second, zap.NewNop())
	if b != nil {
		b.Stop()
		t.Fatal("expected nil batcher when db is nil")
	}
}

func TestLastUsedBatcher_NilLogger_UsesNop(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Should not panic despite nil logger
	b := NewLastUsedBatcher(db, 64, 10*time.Second, nil)
	if b == nil {
		t.Fatal("expected non-nil batcher")
	}
	b.Touch(1) // exercises logger in drop path if it were nil
	b.Stop()
}

func TestLastUsedBatcher_NilDB_NilLogger(t *testing.T) {
	// Both nil — should not panic, logger defaults to nop, then returns nil for nil db
	b := NewLastUsedBatcher(nil, 64, 10*time.Second, nil)
	if b != nil {
		b.Stop()
		t.Fatal("expected nil batcher when db is nil")
	}
}

func TestLastUsedBatcher_NoFlushWhenEmpty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// No expected queries — nothing should be flushed
	b := NewLastUsedBatcher(db, 64, 50*time.Millisecond, zap.NewNop())

	time.Sleep(150 * time.Millisecond)
	b.Stop()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
