package billing

import (
	"context"
	"fmt"

	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/webhook"
	"go.uber.org/zap"
)

// StripeService handles Stripe billing webhooks and key provisioning.
type StripeService struct {
	webhookSecret string
	priceToplan   map[string]string
	repo          *Repository
	cachedRepo    *auth.CachedRepository
}

// NewStripeService creates a billing service backed by Stripe.
// secretKey is used to authenticate API calls to Stripe.
// webhookSecret is used to verify webhook signatures.
// priceMap maps Stripe Price IDs to plan names (e.g., "price_xxx" -> "basic").
func NewStripeService(secretKey, webhookSecret string, priceMap map[string]string, repo *Repository, cachedRepo *auth.CachedRepository) *StripeService {
	stripe.Key = secretKey
	return &StripeService{
		webhookSecret: webhookSecret,
		priceToplan:   priceMap,
		repo:          repo,
		cachedRepo:    cachedRepo,
	}
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
	sess, err := session.Get(event.GetObjectValue("id"), &stripe.CheckoutSessionParams{
		Params: stripe.Params{Context: ctx},
	})
	if err != nil {
		return fmt.Errorf("retrieve checkout session: %w", err)
	}

	stripeCustomerID := sess.Customer.ID
	email := sess.CustomerDetails.Email

	// Idempotency: check if customer already exists
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

	// Determine plan from the subscription's price
	plan := "basic" // default
	if sess.Subscription != nil {
		subscriptionID := sess.Subscription.ID
		// Get the price from the line items
		params := &stripe.CheckoutSessionParams{
			Params: stripe.Params{Context: ctx},
		}
		params.AddExpand("line_items")
		sessExpanded, err := session.Get(subscriptionID, params)
		if err == nil && sessExpanded != nil {
			// Actually, re-fetch the session with line_items expanded
			_ = sessExpanded
		}
		// Use the session line items if available
		if sess.Subscription != nil {
			// Try to match price from subscription metadata or use line items
			for priceID, planName := range s.priceToplan {
				_ = priceID
				_ = planName
			}
		}
		_ = subscriptionID
	}

	// Re-fetch session with line_items expanded to get the price ID
	expandedParams := &stripe.CheckoutSessionParams{
		Params: stripe.Params{Context: ctx},
	}
	expandedParams.AddExpand("line_items")
	expandedSess, err := session.Get(sess.ID, expandedParams)
	if err == nil && expandedSess.LineItems != nil {
		for _, item := range expandedSess.LineItems.Data {
			if item.Price != nil {
				if p, ok := s.priceToplan[item.Price.ID]; ok {
					plan = p
					break
				}
			}
		}
	}

	// Generate API key
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return fmt.Errorf("generate API key: %w", err)
	}
	keyHash := auth.HashKey(rawKey)

	// Create customer with key
	name := email // use email as name if no name provided
	if sess.CustomerDetails.Name != "" {
		name = sess.CustomerDetails.Name
	}

	customerID, err := s.repo.CreateCustomerWithKey(ctx, name, email, plan, stripeCustomerID, keyHash)
	if err != nil {
		return fmt.Errorf("create customer: %w", err)
	}

	// Store provisioned key for one-time retrieval
	if err := s.repo.StoreProvisionedKey(ctx, sess.ID, customerID, rawKey); err != nil {
		return fmt.Errorf("store provisioned key: %w", err)
	}

	logger.Info("new customer provisioned via checkout",
		zap.Int("customer_id", customerID),
		zap.String("plan", plan),
		zap.String("stripe_customer_id", stripeCustomerID),
		zap.String("session_id", sess.ID),
	)

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

	s.cachedRepo.InvalidateAll()

	logger.Info("customer plan updated via subscription change",
		zap.String("stripe_customer_id", stripeCustomerID),
		zap.String("new_plan", plan),
	)

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

	s.cachedRepo.InvalidateAll()

	logger.Info("customer downgraded to free on subscription cancellation",
		zap.String("stripe_customer_id", stripeCustomerID),
	)

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

	s.cachedRepo.InvalidateAll()

	logger.Info("customer downgraded to free on payment failure",
		zap.String("stripe_customer_id", stripeCustomerID),
	)

	return nil
}

// GetProvisionedKey retrieves a one-time provisioned key by checkout session ID.
func (s *StripeService) GetProvisionedKey(ctx context.Context, sessionID string) (string, error) {
	return s.repo.RetrieveProvisionedKey(ctx, sessionID)
}
