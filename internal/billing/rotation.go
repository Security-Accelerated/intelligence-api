package billing

import (
	"context"
	"fmt"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

// KeyRotationRepository is the subset of Repository used for key rotation.
type KeyRotationRepository interface {
	RotateKey(ctx context.Context, customerID int, newKeyHash string, graceExpiry time.Time) error
}

// KeyRotationService issues a fresh API key for a customer and grace-expires
// their previous keys. It depends only on the database — rotation works even
// when Stripe billing is not configured.
type KeyRotationService struct {
	repo      KeyRotationRepository
	grace     time.Duration
	authCache AuthCacheInvalidator
}

func NewKeyRotationService(repo KeyRotationRepository, grace time.Duration, authCache AuthCacheInvalidator) *KeyRotationService {
	if grace <= 0 {
		grace = 24 * time.Hour
	}
	return &KeyRotationService{repo: repo, grace: grace, authCache: authCache}
}

// Rotate generates a new key for the customer, stores its hash, and sets all
// previous keys to expire after the grace window. Returns the raw key (shown
// once, never stored) and the expiry time of the previous keys.
func (s *KeyRotationService) Rotate(ctx context.Context, customerID int) (string, time.Time, error) {
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("rotate key: %w", err)
	}

	graceExpiry := time.Now().UTC().Add(s.grace)
	if err := s.repo.RotateKey(ctx, customerID, auth.HashKey(rawKey), graceExpiry); err != nil {
		return "", time.Time{}, fmt.Errorf("rotate key: %w", err)
	}

	// Drop cached auth entries so expiry takes effect promptly after the
	// grace window rather than lingering for the auth cache TTL.
	if s.authCache != nil {
		s.authCache.InvalidateAll()
	}

	logging.Logger().Info("api key rotated",
		zap.Int("customer_id", customerID),
		zap.Time("old_keys_expire_at", graceExpiry),
	)
	return rawKey, graceExpiry, nil
}
