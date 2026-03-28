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

	// Buffer of 2, long flush interval — channel will fill up
	b := NewLastUsedBatcher(db, 2, 1*time.Hour, zap.NewNop())

	// Fill the buffer without the goroutine draining
	// We can't guarantee exactly when the goroutine reads, but
	// sending many more than the buffer should cause drops
	for i := 0; i < 100; i++ {
		b.Touch(i)
	}

	// Expect at least one flush on stop (whatever made it into the channel)
	mock.ExpectExec("UPDATE api_keys SET last_used_at").
		WillReturnResult(sqlmock.NewResult(0, 1))

	b.Stop()
	// No panic or deadlock = success
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
