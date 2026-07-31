package adminops

import (
	"context"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/security-accelerated/intelligence-api/internal/auth"
)

func newStore(t *testing.T) (*Store, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(db), mock, func() { db.Close() }
}

func TestCreateCustomer_HappyPath(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	id, rawKey, err := s.CreateCustomer(context.Background(), "acme", "acme@example.com", auth.PlanPro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 7 {
		t.Errorf("customer id = %d, want 7", id)
	}

	// The key must match what the running service will accept: 64 lowercase hex
	// characters, exactly as billing.GenerateAPIKey produces.
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(rawKey) {
		t.Errorf("key %q is not 64 lowercase hex characters", rawKey)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCreateCustomer_StoresOnlyTheHash is the reason this package exists rather
// than reusing billing.ProvisionCustomer: the CLI hands the plaintext to the
// operator, so writing a second copy to provisioned_keys would leave a
// retrievable secret nobody is going to collect. sqlmock fails the test on any
// statement that was not expected, so an added INSERT fails here.
func TestCreateCustomer_StoresOnlyTheHash(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	captured := &capturingArg{}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	mock.ExpectExec("INSERT INTO api_keys").
		WithArgs(1, captured).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	_, rawKey, err := s.CreateCustomer(context.Background(), "acme", "", auth.PlanFree)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}

	// The value bound to key_hash must be the digest, and must not be the key
	// itself — a mix-up would store a working credential in plaintext.
	if captured.value == rawKey {
		t.Fatal("the plaintext key was written to key_hash")
	}
	if captured.value != auth.HashKey(rawKey) {
		t.Errorf("key_hash = %q, want the sha256 digest of the issued key", captured.value)
	}
}

// capturingArg matches any argument and records it, so a test can assert on the
// value the statement actually bound rather than only that a statement ran.
type capturingArg struct{ value string }

func (c *capturingArg) Match(v driver.Value) bool {
	s, ok := v.(string)
	if ok {
		c.value = s
	}
	return ok
}

func TestCreateCustomer_RejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, custName, plan string }{
		{"empty name", "", auth.PlanPro},
		{"unknown plan", "acme", "enterprise"},
		{"empty plan", "acme", ""},
		{"plan differing by case", "acme", "PRO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, mock, done := newStore(t)
			defer done()

			// No statements expected: validation must reject before any write.
			if _, _, err := s.CreateCustomer(context.Background(), tc.custName, "", tc.plan); err == nil {
				t.Fatal("expected an error")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("a rejected input still issued a statement: %v", err)
			}
		})
	}
}

func TestCreateCustomer_RollsBackWhenKeyInsertFails(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO customers").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(3))
	mock.ExpectExec("INSERT INTO api_keys").
		WillReturnError(errors.New("unique violation"))
	mock.ExpectRollback()

	// A customer with no key can never authenticate and is invisible to the
	// CLI's own list output, so a partial commit would strand a row nobody
	// would think to look for.
	if _, _, err := s.CreateCustomer(context.Background(), "acme", "", auth.PlanBasic); err == nil {
		t.Fatal("expected an error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestSetPlan_RejectsUnknownPlanBeforeWriting(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	if err := s.SetPlan(context.Background(), 1, "enterprise"); err == nil {
		t.Fatal("expected an error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an invalid plan still issued a statement: %v", err)
	}
}

// TestSetPlan_MissingCustomerIsAnError guards a silent no-op. UPDATE against an
// ID that does not exist succeeds and affects zero rows, so without the
// rows-affected check a mistyped ID would report success having changed nothing.
func TestSetPlan_MissingCustomerIsAnError(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	mock.ExpectExec("UPDATE customers").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := s.SetPlan(context.Background(), 999, auth.PlanPro)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSetActive_MissingCustomerIsAnError(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	mock.ExpectExec("UPDATE customers").
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := s.SetActive(context.Background(), 999, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListCustomers(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	used := created.Add(time.Hour)
	mock.ExpectQuery("FROM customers").WillReturnRows(
		sqlmock.NewRows([]string{"id", "name", "email", "plan", "active", "created_at", "live_keys", "last_used_at"}).
			AddRow(1, "acme", "a@example.com", auth.PlanPro, true, created, 2, used).
			// A customer that has never made a request has a NULL max, which
			// must decode as a zero time rather than failing the whole listing.
			AddRow(2, "beta", "", auth.PlanFree, false, created, 0, nil))

	got, err := s.ListCustomers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d customers, want 2", len(got))
	}
	if got[0].LiveKeys != 2 || !got[0].LastUsedAt.Equal(used) {
		t.Errorf("row 0 = %+v, want 2 live keys and last use %v", got[0], used)
	}
	if !got[1].LastUsedAt.IsZero() {
		t.Errorf("a never-used customer should have a zero LastUsedAt, got %v", got[1].LastUsedAt)
	}
}

func TestListKeys_NullableColumns(t *testing.T) {
	s, mock, done := newStore(t)
	defer done()

	created := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	mock.ExpectQuery("FROM api_keys").WillReturnRows(
		sqlmock.NewRows([]string{"id", "prefix", "created_at", "last_used_at", "expires_at"}).
			AddRow(10, "abc123def456", created, nil, nil))

	got, err := s.ListKeys(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d keys, want 1", len(got))
	}
	if got[0].Expired(created.Add(time.Hour)) {
		t.Error("a key with no expiry must never report as expired")
	}
}

func TestKey_Expired(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"no expiry set", time.Time{}, false},
		{"grace window still open", now.Add(time.Hour), false},
		{"grace window closed", now.Add(-time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Key{ExpiresAt: tc.expires}).Expired(now); got != tc.want {
				t.Errorf("Expired() = %v, want %v", got, tc.want)
			}
		})
	}
}
