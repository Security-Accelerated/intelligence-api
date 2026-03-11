package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func TestFingerprintService_EngineNotNil(t *testing.T) {
	svc := NewFingerprintService(nil)
	if svc.Engine() == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestFingerprintService_GetRules_Empty(t *testing.T) {
	svc := NewFingerprintService(nil)
	rules := svc.GetRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestFingerprintService_GetRules_AfterLoad(t *testing.T) {
	svc := NewFingerprintService(nil)
	testRules := []domain.TechRule{
		{Name: "Nginx", Category: "web-server"},
		{Name: "PHP", Category: "language"},
	}
	svc.Engine().LoadRules(testRules)

	rules := svc.GetRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Name != "Nginx" {
		t.Errorf("rules[0].Name = %q, want %q", rules[0].Name, "Nginx")
	}
}

// --- LoadFromDB tests ---

func TestFingerprintService_LoadFromDB_ExistingRules(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rules := []domain.TechRule{
		{Name: "Nginx", Category: "web-server", Headers: map[string]string{"Server": "nginx"}},
		{Name: "PHP", Category: "language", Headers: map[string]string{"X-Powered-By": "PHP"}},
	}
	data, _ := json.Marshal(rules)

	mock.ExpectQuery("SELECT rules FROM fingerprint_rules").
		WillReturnRows(sqlmock.NewRows([]string{"rules"}).AddRow(data))

	svc := NewFingerprintService(db)
	if err := svc.LoadFromDB(context.Background()); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	loaded := svc.GetRules()
	if len(loaded) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(loaded))
	}
	if loaded[0].Name != "Nginx" {
		t.Errorf("rules[0].Name = %q, want %q", loaded[0].Name, "Nginx")
	}
	if loaded[1].Name != "PHP" {
		t.Errorf("rules[1].Name = %q, want %q", loaded[1].Name, "PHP")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestFingerprintService_LoadFromDB_NoRows_SeedsDefaults(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// First query returns no rows → triggers seed path
	mock.ExpectQuery("SELECT rules FROM fingerprint_rules").
		WillReturnRows(sqlmock.NewRows([]string{"rules"}))

	// Seed inserts embedded defaults
	mock.ExpectExec("INSERT INTO fingerprint_rules").
		WillReturnResult(sqlmock.NewResult(1, 1))

	svc := NewFingerprintService(db)
	if err := svc.LoadFromDB(context.Background()); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	// Engine should now have the embedded default rules
	rules := svc.GetRules()
	if len(rules) == 0 {
		t.Error("expected default rules to be loaded after seeding")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestFingerprintService_LoadFromDB_InvalidJSON(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT rules FROM fingerprint_rules").
		WillReturnRows(sqlmock.NewRows([]string{"rules"}).AddRow([]byte("not json")))

	svc := NewFingerprintService(db)
	if err := svc.LoadFromDB(context.Background()); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFingerprintService_LoadFromDB_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT rules FROM fingerprint_rules").
		WillReturnError(context.DeadlineExceeded)

	svc := NewFingerprintService(db)
	if err := svc.LoadFromDB(context.Background()); err == nil {
		t.Fatal("expected error for query failure")
	}
}

// --- UpdateRules tests ---

func TestFingerprintService_UpdateRules_Valid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO fingerprint_rules").
		WillReturnResult(sqlmock.NewResult(1, 1))

	svc := NewFingerprintService(db)
	rules := []domain.TechRule{
		{Name: "Cloudflare", Category: "cdn", Headers: map[string]string{"Server": "cloudflare"}},
	}

	if err := svc.UpdateRules(context.Background(), rules, 100); err != nil {
		t.Fatalf("UpdateRules: %v", err)
	}

	// Engine should be hot-reloaded with new rules
	loaded := svc.GetRules()
	if len(loaded) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(loaded))
	}
	if loaded[0].Name != "Cloudflare" {
		t.Errorf("rules[0].Name = %q, want %q", loaded[0].Name, "Cloudflare")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestFingerprintService_UpdateRules_EmptyName(t *testing.T) {
	svc := NewFingerprintService(nil)
	rules := []domain.TechRule{
		{Name: "", Category: "web-server"},
	}

	err := svc.UpdateRules(context.Background(), rules, 100)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestFingerprintService_UpdateRules_InvalidCategory(t *testing.T) {
	svc := NewFingerprintService(nil)
	rules := []domain.TechRule{
		{Name: "TestTech", Category: "invalid-category"},
	}

	err := svc.UpdateRules(context.Background(), rules, 100)
	if err == nil {
		t.Fatal("expected error for invalid category")
	}
}

func TestFingerprintService_UpdateRules_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO fingerprint_rules").
		WillReturnError(context.DeadlineExceeded)

	svc := NewFingerprintService(db)
	rules := []domain.TechRule{
		{Name: "TestTech", Category: "web-server", Headers: map[string]string{"Server": "test"}},
	}

	if err := svc.UpdateRules(context.Background(), rules, 100); err == nil {
		t.Fatal("expected error for DB failure")
	}

	// Engine should NOT be reloaded on DB failure
	loaded := svc.GetRules()
	if len(loaded) != 0 {
		t.Errorf("expected 0 rules after failed update, got %d", len(loaded))
	}
}

func TestFingerprintService_UpdateRules_MultipleRulesValidation(t *testing.T) {
	svc := NewFingerprintService(nil)

	// Second rule has invalid category — should fail before DB insert
	rules := []domain.TechRule{
		{Name: "Good", Category: "web-server"},
		{Name: "Bad", Category: "nonexistent"},
	}

	err := svc.UpdateRules(context.Background(), rules, 100)
	if err == nil {
		t.Fatal("expected validation error")
	}
}
