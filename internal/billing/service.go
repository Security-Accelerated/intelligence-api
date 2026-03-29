package billing

import "context"

// Service handles billing operations including webhook processing and key provisioning.
type Service interface {
	HandleWebhook(ctx context.Context, payload []byte, sigHeader string) error
	GetProvisionedKey(ctx context.Context, sessionID string) (string, error)
}

// BillingRepository abstracts the database operations needed by the billing service.
type BillingRepository interface {
	CustomerExistsByStripeID(ctx context.Context, stripeCustomerID string) (bool, error)
	ProvisionCustomer(ctx context.Context, name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey string) (int, error)
	RetrieveProvisionedKey(ctx context.Context, sessionID string) (string, error)
	UpdatePlan(ctx context.Context, stripeCustomerID, plan string) error
	DowngradeToFree(ctx context.Context, stripeCustomerID string) error
}

// AuthCacheInvalidator allows clearing the auth cache after plan changes.
type AuthCacheInvalidator interface {
	InvalidateAll()
}
