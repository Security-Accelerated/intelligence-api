package service

import (
	"testing"

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
