package billing

import (
	"context"
	"fmt"

	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/notifications"
	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/checkout/session"
	"github.com/stripe/stripe-go/v84/webhook"
	"go.uber.org/zap"
)

// StripeService handles Stripe billing webhooks and key provisioning.
type StripeService struct {
	webhookSecret string
	priceToplan   map[string]string
	repo          BillingRepository
	authCache     AuthCacheInvalidator
	notifier      notifications.Notifier

	// getSession fetches a checkout session from Stripe. Separated from the
	// SDK-level package function so tests can inject a stub and verify the
	// handler's behavior without network calls.
	getSession func(ctx context.Context, sessionID string, expandLineItems bool) (*stripe.CheckoutSession, error)
}

// NewStripeService creates a billing service backed by Stripe.
// secretKey is used to authenticate API calls to Stripe.
// webhookSecret is used to verify webhook signatures.
// priceMap maps Stripe Price IDs to plan names (e.g., "price_xxx" -> "basic").
func NewStripeService(secretKey, webhookSecret string, priceMap map[string]string, repo BillingRepository, authCache AuthCacheInvalidator, notifier notifications.Notifier) *StripeService {
	stripe.Key = secretKey
	return &StripeService{
		webhookSecret: webhookSecret,
		priceToplan:   priceMap,
		repo:          repo,
		authCache:     authCache,
		notifier:      notifier,
		getSession:    realGetSession,
	}
}

// realGetSession is the production checkout-session fetcher. It calls the
// Stripe SDK and, when expandLineItems is true, expands the line_items field
// so the plan can be resolved from the purchased price IDs.
func realGetSession(ctx context.Context, sessionID string, expandLineItems bool) (*stripe.CheckoutSession, error) {
	params := &stripe.CheckoutSessionParams{
		Params: stripe.Params{Context: ctx},
	}
	if expandLineItems {
		params.AddExpand("line_items")
	}
	return session.Get(sessionID, params)
}

// HandleWebhook verifies a Stripe webhook signature and processes the event.
func (s *StripeService) HandleWebhook(ctx context.Context, payload []byte, sigHeader string) error {
	event, err := webhook.ConstructEvent(payload, sigHeader, s.webhookSecret)
	if err != nil {
		return fmt.Errorf("verify webhook signature: %w", err)
	}

	logger := logging.Logger()

	switch event.Type {
	case "checkout.session.completed":
		return s.handleCheckoutCompleted(ctx, &event, logger)
	case "customer.subscription.updated":
		return s.handleSubscriptionUpdated(ctx, &event, logger)
	case "customer.subscription.deleted":
		return s.handleSubscriptionDeleted(ctx, &event, logger)
	case "invoice.payment_failed":
		return s.handlePaymentFailed(ctx, &event, logger)
	default:
		logger.Debug("unhandled stripe event type", zap.String("type", string(event.Type)))
		return nil
	}
}

func (s *StripeService) handleCheckoutCompleted(ctx context.Context, event *stripe.Event, logger *zap.Logger) error {
	sess, err := s.getSession(ctx, event.GetObjectValue("id"), false)
	if err != nil {
		return fmt.Errorf("retrieve checkout session: %w", err)
	}
	if sess.Customer == nil {
		return fmt.Errorf("checkout session %s missing customer", sess.ID)
	}

	stripeCustomerID := sess.Customer.ID
	var email string
	if sess.CustomerDetails != nil {
		email = sess.CustomerDetails.Email
	}

	// Idempotency: customer creation, api_key, and provisioned_key are all in one
	// transaction (ProvisionCustomer), so if the customer exists, everything succeeded.
	exists, err := s.repo.CustomerExistsByStripeID(ctx, stripeCustomerID)
	if err != nil {
		return fmt.Errorf("check existing customer: %w", err)
	}
	if exists {
		logger.Info("checkout webhook for existing customer, skipping",
			zap.String("stripe_customer_id", stripeCustomerID),
		)
		return nil
	}

	// Determine plan from the checkout session's line items.
	// This fetch must succeed — a failure here would silently default a paid
	// customer to the wrong plan. Returning an error causes Stripe to retry.
	expandedSess, err := s.getSession(ctx, sess.ID, true)
	if err != nil {
		return fmt.Errorf("retrieve checkout line items: %w", err)
	}

	var plan string
	if expandedSess.LineItems != nil {
		for _, item := range expandedSess.LineItems.Data {
			if item.Price != nil {
				if p, ok := s.priceToplan[item.Price.ID]; ok {
					plan = p
					break
				}
			}
		}
	}
	if plan == "" {
		return fmt.Errorf("could not determine plan from checkout session %s: no matching price ID", sess.ID)
	}

	// Generate API key
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return fmt.Errorf("generate API key: %w", err)
	}
	keyHash := auth.HashKey(rawKey)

	// Use email as name if no name provided
	name := email
	if sess.CustomerDetails != nil && sess.CustomerDetails.Name != "" {
		name = sess.CustomerDetails.Name
	}

	// Atomically create customer, api_key, and provisioned_key in one transaction.
	// This prevents partial failures that would leave a customer without a retrievable key.
	customerID, err := s.repo.ProvisionCustomer(ctx, name, email, plan, stripeCustomerID, keyHash, sess.ID, rawKey)
	if err != nil {
		return fmt.Errorf("provision customer: %w", err)
	}

	logger.Info("new customer provisioned via checkout",
		zap.Int("customer_id", customerID),
		zap.String("plan", plan),
		zap.String("stripe_customer_id", stripeCustomerID),
		zap.String("session_id", sess.ID),
	)

	s.notify(ctx, "New Subscriber", fmt.Sprintf("%s signed up for the %s plan", email, plan))

	return nil
}

func (s *StripeService) handleSubscriptionUpdated(ctx context.Context, event *stripe.Event, logger *zap.Logger) error {
	stripeCustomerID := event.GetObjectValue("customer")
	if stripeCustomerID == "" {
		return fmt.Errorf("subscription update missing customer ID")
	}

	// Get the price ID from the subscription items
	priceID := event.GetObjectValue("items", "data", "0", "price", "id")
	plan, ok := s.priceToplan[priceID]
	if !ok {
		logger.Warn("unknown price ID in subscription update, skipping",
			zap.String("price_id", priceID),
			zap.String("stripe_customer_id", stripeCustomerID),
		)
		return nil
	}

	if err := s.repo.UpdatePlan(ctx, stripeCustomerID, plan); err != nil {
		return fmt.Errorf("update plan: %w", err)
	}

	s.authCache.InvalidateAll()

	logger.Info("customer plan updated via subscription change",
		zap.String("stripe_customer_id", stripeCustomerID),
		zap.String("new_plan", plan),
	)

	s.notify(ctx, "Plan Change", fmt.Sprintf("Customer %s changed to %s plan", stripeCustomerID, plan))

	return nil
}

func (s *StripeService) handleSubscriptionDeleted(ctx context.Context, event *stripe.Event, logger *zap.Logger) error {
	stripeCustomerID := event.GetObjectValue("customer")
	if stripeCustomerID == "" {
		return fmt.Errorf("subscription deletion missing customer ID")
	}

	if err := s.repo.DowngradeToFree(ctx, stripeCustomerID); err != nil {
		return fmt.Errorf("downgrade on cancellation: %w", err)
	}

	s.authCache.InvalidateAll()

	logger.Info("customer downgraded to free on subscription cancellation",
		zap.String("stripe_customer_id", stripeCustomerID),
	)

	s.notify(ctx, "Subscription Cancelled", fmt.Sprintf("Customer %s cancelled their subscription", stripeCustomerID))

	return nil
}

func (s *StripeService) handlePaymentFailed(ctx context.Context, event *stripe.Event, logger *zap.Logger) error {
	stripeCustomerID := event.GetObjectValue("customer")
	if stripeCustomerID == "" {
		return fmt.Errorf("payment failure missing customer ID")
	}

	if err := s.repo.DowngradeToFree(ctx, stripeCustomerID); err != nil {
		return fmt.Errorf("downgrade on payment failure: %w", err)
	}

	s.authCache.InvalidateAll()

	logger.Info("customer downgraded to free on payment failure",
		zap.String("stripe_customer_id", stripeCustomerID),
	)

	s.notify(ctx, "Payment Failed", fmt.Sprintf("Payment failed for customer %s, downgraded to free", stripeCustomerID))

	return nil
}

// notify sends a push notification asynchronously. Failures are logged but not returned.
func (s *StripeService) notify(ctx context.Context, title, message string) {
	go func() {
		if err := s.notifier.Send(ctx, title, message, 0); err != nil {
			logging.Logger().Warn("billing notification failed", zap.Error(err))
		}
	}()
}

// GetProvisionedKey retrieves a one-time provisioned key by checkout session ID.
func (s *StripeService) GetProvisionedKey(ctx context.Context, sessionID string) (string, error) {
	return s.repo.RetrieveProvisionedKey(ctx, sessionID)
}
