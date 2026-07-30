package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/security-accelerated/intelligence-api/internal/auth"
)

type mockRotationRepo struct {
	customerID  int
	keyHash     string
	graceExpiry time.Time
	err         error
}

func (m *mockRotationRepo) RotateKey(_ context.Context, customerID int, newKeyHash string, graceExpiry time.Time) error {
	m.customerID = customerID
	m.keyHash = newKeyHash
	m.graceExpiry = graceExpiry
	return m.err
}

type mockInvalidator struct{ calls int }

func (m *mockInvalidator) InvalidateAll() { m.calls++ }

func TestKeyRotationService_Rotate(t *testing.T) {
	repo := &mockRotationRepo{}
	inv := &mockInvalidator{}
	svc := NewKeyRotationService(repo, time.Hour, inv)

	rawKey, expiry, err := svc.Rotate(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rawKey) != 64 {
		t.Errorf("rawKey length = %d, want 64", len(rawKey))
	}
	if repo.customerID != 42 {
		t.Errorf("customerID = %d, want 42", repo.customerID)
	}
	if repo.keyHash != auth.HashKey(rawKey) {
		t.Error("stored hash does not match returned raw key")
	}
	if repo.keyHash == rawKey {
		t.Error("raw key must never be stored directly")
	}
	wantExpiry := time.Now().UTC().Add(time.Hour)
	if expiry.Before(wantExpiry.Add(-time.Minute)) || expiry.After(wantExpiry.Add(time.Minute)) {
		t.Errorf("expiry = %v, want ~%v", expiry, wantExpiry)
	}
	if inv.calls != 1 {
		t.Errorf("auth cache invalidations = %d, want 1", inv.calls)
	}
}

func TestKeyRotationService_RepoError(t *testing.T) {
	repo := &mockRotationRepo{err: errors.New("db down")}
	inv := &mockInvalidator{}
	svc := NewKeyRotationService(repo, time.Hour, inv)

	if _, _, err := svc.Rotate(context.Background(), 1); err == nil {
		t.Fatal("expected error")
	}
	if inv.calls != 0 {
		t.Errorf("auth cache invalidated on failure (calls=%d), want 0", inv.calls)
	}
}

func TestKeyRotationService_DefaultGrace(t *testing.T) {
	svc := NewKeyRotationService(&mockRotationRepo{}, 0, nil)
	if svc.grace != 24*time.Hour {
		t.Errorf("grace = %v, want 24h default", svc.grace)
	}
}

func TestRepository_RetrieveProvisionedKey_BlanksPlaintext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// The retrieval statement must blank the stored plaintext while returning
	// the pre-update value via the CTE.
	mock.ExpectQuery(`SET retrieved = true, raw_key = ''`).
		WithArgs("sess_123").
		WillReturnRows(sqlmock.NewRows([]string{"raw_key"}).AddRow("the-raw-key"))

	repo := NewRepository(db)
	key, err := repo.RetrieveProvisionedKey(context.Background(), "sess_123")
	if err != nil {
		t.Fatalf("RetrieveProvisionedKey: %v", err)
	}
	if key != "the-raw-key" {
		t.Errorf("key = %q, want the-raw-key", key)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestStartProvisionedKeyCleanup_RunsImmediately(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM provisioned_keys").
		WillReturnResult(sqlmock.NewResult(0, 2))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartProvisionedKeyCleanup(ctx, NewRepository(db), time.Hour)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mock.ExpectationsWereMet() == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cleanup did not run: %v", mock.ExpectationsWereMet())
}

func TestRepository_RotateKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expiry := time.Now().UTC().Add(time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO api_keys").
		WithArgs(42, "newhash").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))
	mock.ExpectExec("UPDATE api_keys").
		WithArgs(expiry, 42, 7).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	repo := NewRepository(db)
	if err := repo.RotateKey(context.Background(), 42, "newhash", expiry); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestRepository_RotateKey_RollbackOnUpdateFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expiry := time.Now().UTC().Add(time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO api_keys").
		WithArgs(42, "newhash").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))
	mock.ExpectExec("UPDATE api_keys").
		WillReturnError(errors.New("update failed"))
	mock.ExpectRollback()

	repo := NewRepository(db)
	if err := repo.RotateKey(context.Background(), 42, "newhash", expiry); err == nil {
		t.Fatal("expected error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
