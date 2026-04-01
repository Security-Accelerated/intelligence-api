package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// ValidationError indicates a client input error (as opposed to a server/database error).
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

// FingerprintService manages technology fingerprint rules in PostgreSQL
// and exposes a FingerprintEngine for runtime matching.
type FingerprintService struct {
	db     *sql.DB
	engine *domain.FingerprintEngine
}

// NewFingerprintService creates a new service with an empty engine.
func NewFingerprintService(db *sql.DB) *FingerprintService {
	return &FingerprintService{
		db:     db,
		engine: domain.NewFingerprintEngine(),
	}
}

// LoadFromDB loads the latest rules from PostgreSQL. If no rows exist,
// it seeds the database with embedded defaults.
func (s *FingerprintService) LoadFromDB(ctx context.Context) error {
	var rulesJSON []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT rules FROM fingerprint_rules ORDER BY id DESC LIMIT 1",
	).Scan(&rulesJSON)

	if err == sql.ErrNoRows {
		defaults, parseErr := domain.DefaultRules()
		if parseErr != nil {
			return fmt.Errorf("load default rules: %w", parseErr)
		}
		s.engine.LoadRules(defaults)

		data, err := json.Marshal(defaults)
		if err != nil {
			return fmt.Errorf("marshal default rules: %w", err)
		}
		_, insertErr := s.db.ExecContext(ctx,
			"INSERT INTO fingerprint_rules (rules) VALUES ($1)", data)
		if insertErr != nil {
			return fmt.Errorf("seed default rules: %w", insertErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("query fingerprint rules: %w", err)
	}

	var rules []domain.TechRule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return fmt.Errorf("parse fingerprint rules from DB: %w", err)
	}
	s.engine.LoadRules(rules)
	return nil
}

// UpdateRules validates, persists, and hot-reloads new rules.
func (s *FingerprintService) UpdateRules(ctx context.Context, rules []domain.TechRule, apiKeyID int) error {
	for i, r := range rules {
		if r.Name == "" {
			return &ValidationError{Message: fmt.Sprintf("rule %d: name is required", i)}
		}
		if !domain.ValidCategories[r.Category] {
			return &ValidationError{Message: fmt.Sprintf("rule %d (%s): invalid category %q", i, r.Name, r.Category)}
		}
	}

	data, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		"INSERT INTO fingerprint_rules (rules, updated_by) VALUES ($1, $2)",
		data, apiKeyID)
	if err != nil {
		return fmt.Errorf("insert fingerprint rules: %w", err)
	}

	s.engine.LoadRules(rules)
	return nil
}

// GetRules returns the current ruleset.
func (s *FingerprintService) GetRules() []domain.TechRule {
	return s.engine.Rules()
}

// Engine returns the underlying FingerprintEngine for use by the domain service.
func (s *FingerprintService) Engine() *domain.FingerprintEngine {
	return s.engine
}
