package billing

import "context"

// Service handles billing operations including webhook processing and key provisioning.
type Service interface {
	HandleWebhook(ctx context.Context, payload []byte, sigHeader string) error
	GetProvisionedKey(ctx context.Context, sessionID string) (string, error)
}
