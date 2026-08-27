package billing

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// --- ProvisionCustomer ---

func TestProvisionCustomer_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WithArgs("acme", "acme@example.com", "cus_123", "pro").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectExec("INSERT INTO api_keys").
		WithArgs(42, "hashvalue").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO provisioned_keys").
		WithArgs("sess_abc", 42, "rawkey123").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	repo := NewRepository(db)
	id, err := repo.ProvisionCustomer(context.Background(), "acme", "acme@example.com", "pro", "cus_123", "hashvalue", "sess_abc", "rawkey123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 42 {
		t.Errorf("customer id = %d, want 42", id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestProvisionCustomer_BeginTxError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin().WillReturnError(errors.New("connection refused"))

	repo := NewRepository(db)
	_, err = repo.ProvisionCustomer(context.Background(), "acme", "acme@example.com", "pro", "cus_123", "hashvalue", "sess_abc", "rawkey123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestProvisionCustomer_InsertCustomerError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WithArgs("acme", "acme@example.com", "cus_123", "pro").
		WillReturnError(errors.New("duplicate key"))
	mock.ExpectRollback()

	repo := NewRepository(db)
	_, err = repo.ProvisionCustomer(context.Background(), "acme", "acme@example.com", "pro", "cus_123", "hashvalue", "sess_abc", "rawkey123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestProvisionCustomer_InsertKeyError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WithArgs("acme", "acme@example.com", "cus_123", "pro").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectExec("INSERT INTO api_keys").
		WithArgs(42, "hashvalue").
		WillReturnError(errors.New("constraint violation"))
	mock.ExpectRollback()

	repo := NewRepository(db)
	_, err = repo.ProvisionCustomer(context.Background(), "acme", "acme@example.com", "pro", "cus_123", "hashvalue", "sess_abc", "rawkey123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestProvisionCustomer_InsertProvisionedKeyError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WithArgs("acme", "acme@example.com", "cus_123", "pro").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectExec("INSERT INTO api_keys").
		WithArgs(42, "hashvalue").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO provisioned_keys").
		WithArgs("sess_abc", 42, "rawkey123").
		WillReturnError(errors.New("session conflict"))
	mock.ExpectRollback()

	repo := NewRepository(db)
	_, err = repo.ProvisionCustomer(context.Background(), "acme", "acme@example.com", "pro", "cus_123", "hashvalue", "sess_abc", "rawkey123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestProvisionCustomer_CommitError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WithArgs("acme", "acme@example.com", "cus_123", "pro").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(42))
	mock.ExpectExec("INSERT INTO api_keys").
		WithArgs(42, "hashvalue").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO provisioned_keys").
		WithArgs("sess_abc", 42, "rawkey123").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))

	repo := NewRepository(db)
	_, err = repo.ProvisionCustomer(context.Background(), "acme", "acme@example.com", "pro", "cus_123", "hashvalue", "sess_abc", "rawkey123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// --- RetrieveProvisionedKey ---

func TestRetrieveProvisionedKey_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("UPDATE provisioned_keys").
		WithArgs("sess_abc").
		WillReturnRows(sqlmock.NewRows([]string{"raw_key"}).AddRow("rawkey123"))

	repo := NewRepository(db)
	key, err := repo.RetrieveProvisionedKey(context.Background(), "sess_abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "rawkey123" {
		t.Errorf("key = %q, want %q", key, "rawkey123")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRetrieveProvisionedKey_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Atomic UPDATE returns no rows
	mock.ExpectQuery("UPDATE provisioned_keys").
		WithArgs("sess_missing").
		WillReturnError(sql.ErrNoRows)
	// Classification query also finds nothing
	mock.ExpectQuery("SELECT retrieved, expires_at FROM provisioned_keys").
		WithArgs("sess_missing").
		WillReturnError(sql.ErrNoRows)

	repo := NewRepository(db)
	_, err = repo.RetrieveProvisionedKey(context.Background(), "sess_missing")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRetrieveProvisionedKey_AlreadyRetrieved(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	futureTime := time.Now().Add(1 * time.Hour)

	// Atomic UPDATE returns no rows (already retrieved)
	mock.ExpectQuery("UPDATE provisioned_keys").
		WithArgs("sess_abc").
		WillReturnError(sql.ErrNoRows)
	// Classification query reveals it was already retrieved
	mock.ExpectQuery("SELECT retrieved, expires_at FROM provisioned_keys").
		WithArgs("sess_abc").
		WillReturnRows(sqlmock.NewRows([]string{"retrieved", "expires_at"}).
			AddRow(true, futureTime))

	repo := NewRepository(db)
	_, err = repo.RetrieveProvisionedKey(context.Background(), "sess_abc")
	if !errors.Is(err, ErrKeyRetrieved) {
		t.Fatalf("err = %v, want ErrKeyRetrieved", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRetrieveProvisionedKey_Expired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pastTime := time.Now().Add(-1 * time.Hour)

	// Atomic UPDATE returns no rows (expired)
	mock.ExpectQuery("UPDATE provisioned_keys").
		WithArgs("sess_abc").
		WillReturnError(sql.ErrNoRows)
	// Classification query reveals it expired
	mock.ExpectQuery("SELECT retrieved, expires_at FROM provisioned_keys").
		WithArgs("sess_abc").
		WillReturnRows(sqlmock.NewRows([]string{"retrieved", "expires_at"}).
			AddRow(false, pastTime))

	repo := NewRepository(db)
	_, err = repo.RetrieveProvisionedKey(context.Background(), "sess_abc")
	if !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("err = %v, want ErrKeyExpired", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRetrieveProvisionedKey_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("UPDATE provisioned_keys").
		WithArgs("sess_abc").
		WillReturnError(errors.New("connection refused"))

	repo := NewRepository(db)
	_, err = repo.RetrieveProvisionedKey(context.Background(), "sess_abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRetrieveProvisionedKey_ClassificationDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Atomic UPDATE returns no rows
	mock.ExpectQuery("UPDATE provisioned_keys").
		WithArgs("sess_abc").
		WillReturnError(sql.ErrNoRows)
	// Classification query hits a real DB error — should propagate, not mask as ErrKeyNotFound
	mock.ExpectQuery("SELECT retrieved, expires_at FROM provisioned_keys").
		WithArgs("sess_abc").
		WillReturnError(errors.New("connection reset"))

	repo := NewRepository(db)
	_, err = repo.RetrieveProvisionedKey(context.Background(), "sess_abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatal("DB error was incorrectly mapped to ErrKeyNotFound")
	}
	if errors.Is(err, ErrKeyRetrieved) {
		t.Fatal("DB error was incorrectly mapped to ErrKeyRetrieved")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// --- UpdatePlan ---

func TestUpdatePlan_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE customers SET plan").
		WithArgs("pro", "cus_123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(db)
	err = repo.UpdatePlan(context.Background(), "cus_123", "pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUpdatePlan_NoRowsAffected(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE customers SET plan").
		WithArgs("pro", "cus_nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	repo := NewRepository(db)
	err = repo.UpdatePlan(context.Background(), "cus_nonexistent", "pro")
	if err == nil {
		t.Fatal("expected error for no rows affected, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUpdatePlan_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE customers SET plan").
		WithArgs("pro", "cus_123").
		WillReturnError(errors.New("db error"))

	repo := NewRepository(db)
	err = repo.UpdatePlan(context.Background(), "cus_123", "pro")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestUpdatePlan_RowsAffectedError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE customers SET plan").
		WithArgs("pro", "cus_123").
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows affected failed")))

	repo := NewRepository(db)
	err = repo.UpdatePlan(context.Background(), "cus_123", "pro")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// --- DowngradeToFree ---

func TestDowngradeToFree_DelegatesToUpdatePlan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE customers SET plan").
		WithArgs("free", "cus_123").
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewRepository(db)
	err = repo.DowngradeToFree(context.Background(), "cus_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// --- CleanupExpiredKeys ---

func TestCleanupExpiredKeys_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM provisioned_keys").
		WillReturnResult(sqlmock.NewResult(0, 3))

	repo := NewRepository(db)
	err = repo.CleanupExpiredKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestCleanupExpiredKeys_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("DELETE FROM provisioned_keys").
		WillReturnError(errors.New("db error"))

	repo := NewRepository(db)
	err = repo.CleanupExpiredKeys(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// --- DeactivateStaleKeys ---

func TestDeactivateStaleKeys_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cutoff := time.Now().Add(-30 * 24 * time.Hour)

	mock.ExpectExec("UPDATE customers SET active = false").
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 5))

	repo := NewRepository(db)
	count, err := repo.DeactivateStaleKeys(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestDeactivateStaleKeys_ExecError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cutoff := time.Now().Add(-30 * 24 * time.Hour)

	mock.ExpectExec("UPDATE customers SET active = false").
		WithArgs(cutoff).
		WillReturnError(errors.New("db error"))

	repo := NewRepository(db)
	count, err := repo.DeactivateStaleKeys(context.Background(), cutoff)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 on error", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestDeactivateStaleKeys_RowsAffectedError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cutoff := time.Now().Add(-30 * 24 * time.Hour)

	mock.ExpectExec("UPDATE customers SET active = false").
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows affected failed")))

	repo := NewRepository(db)
	count, err := repo.DeactivateStaleKeys(context.Background(), cutoff)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 on error", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// --- CustomerExistsByStripeID ---

func TestCustomerExistsByStripeID_Exists(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("cus_123").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	repo := NewRepository(db)
	exists, err := repo.CustomerExistsByStripeID(context.Background(), "cus_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected true, got false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestCustomerExistsByStripeID_NotExists(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("cus_unknown").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	repo := NewRepository(db)
	exists, err := repo.CustomerExistsByStripeID(context.Background(), "cus_unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected false, got true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestCustomerExistsByStripeID_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("cus_123").
		WillReturnError(errors.New("db error"))

	repo := NewRepository(db)
	exists, err := repo.CustomerExistsByStripeID(context.Background(), "cus_123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if exists {
		t.Error("expected false on error, got true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
