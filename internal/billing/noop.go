package billing

import (
	"context"
	"errors"
)

var errNotConfigured = errors.New("billing not configured")

// NoopService returns errors indicating billing is not configured.
// Used when Stripe credentials are absent so the app starts cleanly.
type NoopService struct{}

func (n *NoopService) HandleWebhook(_ context.Context, _ []byte, _ string) error {
	return errNotConfigured
}

func (n *NoopService) GetProvisionedKey(_ context.Context, _ string) (string, error) {
	return "", errNotConfigured
}
