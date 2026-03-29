package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v84"
	"go.uber.org/zap"
)

type mockNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
}

type notifyCall struct {
	title    string
	message  string
	priority int
}

func (m *mockNotifier) Send(_ context.Context, title, message string, priority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, notifyCall{title, message, priority})
	return nil
}

func (m *mockNotifier) getCalls() []notifyCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]notifyCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

func TestStripeService_Notify(t *testing.T) {
	n := &mockNotifier{}
	svc := &StripeService{notifier: n}

	svc.notify(context.Background(), "Test Title", "Test message")

	// notify is async, give it a moment
	time.Sleep(50 * time.Millisecond)

	calls := n.getCalls()
	if len(calls) != 1 {
		t.Fatalf("got %d notify calls, want 1", len(calls))
	}
	if calls[0].title != "Test Title" {
		t.Errorf("title = %q, want %q", calls[0].title, "Test Title")
	}
	if calls[0].message != "Test message" {
		t.Errorf("message = %q, want %q", calls[0].message, "Test message")
	}
	if calls[0].priority != 0 {
		t.Errorf("priority = %d, want 0", calls[0].priority)
	}
}

func TestStripeService_NotifyMultiple(t *testing.T) {
	n := &mockNotifier{}
	svc := &StripeService{notifier: n}

	svc.notify(context.Background(), "New Subscriber", "user@example.com signed up for basic")
	svc.notify(context.Background(), "Subscription Cancelled", "Customer cus_123 cancelled")

	time.Sleep(50 * time.Millisecond)

	calls := n.getCalls()
	if len(calls) != 2 {
		t.Fatalf("got %d notify calls, want 2", len(calls))
	}
}

// --- Mock types for webhook handler tests ---

type mockBillingRepo struct {
	updatePlanCalls []struct{ customerID, plan string }
	downgradeCalls  []string
	updatePlanErr   error
	downgradeErr    error
}

func (m *mockBillingRepo) CustomerExistsByStripeID(context.Context, string) (bool, error) {
	return false, nil
}
func (m *mockBillingRepo) ProvisionCustomer(context.Context, string, string, string, string, string, string, string) (int, error) {
	return 0, nil
}
func (m *mockBillingRepo) RetrieveProvisionedKey(context.Context, string) (string, error) {
	return "", nil
}
func (m *mockBillingRepo) UpdatePlan(_ context.Context, customerID, plan string) error {
	m.updatePlanCalls = append(m.updatePlanCalls, struct{ customerID, plan string }{customerID, plan})
	return m.updatePlanErr
}
func (m *mockBillingRepo) DowngradeToFree(_ context.Context, customerID string) error {
	m.downgradeCalls = append(m.downgradeCalls, customerID)
	return m.downgradeErr
}

type mockAuthCache struct {
	invalidated bool
}

func (m *mockAuthCache) InvalidateAll() {
	m.invalidated = true
}

func newTestStripeService(repo *mockBillingRepo, authCache *mockAuthCache, notifier *mockNotifier) *StripeService {
	return &StripeService{
		priceToplan: map[string]string{"price_basic": "basic", "price_pro": "pro"},
		repo:        repo,
		authCache:   authCache,
		notifier:    notifier,
	}
}

// --- Webhook handler tests ---

func TestHandleSubscriptionUpdated_HappyPath(t *testing.T) {
	repo := &mockBillingRepo{}
	authCache := &mockAuthCache{}
	notifier := &mockNotifier{}
	svc := newTestStripeService(repo, authCache, notifier)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{
				"customer": "cus_123",
				"items": map[string]interface{}{
					"data": []interface{}{
						map[string]interface{}{
							"price": map[string]interface{}{
								"id": "price_pro",
							},
						},
					},
				},
			},
		},
	}

	err := svc.handleSubscriptionUpdated(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.updatePlanCalls) != 1 {
		t.Fatalf("expected 1 UpdatePlan call, got %d", len(repo.updatePlanCalls))
	}
	if repo.updatePlanCalls[0].customerID != "cus_123" || repo.updatePlanCalls[0].plan != "pro" {
		t.Errorf("UpdatePlan(%q, %q), want (%q, %q)", repo.updatePlanCalls[0].customerID, repo.updatePlanCalls[0].plan, "cus_123", "pro")
	}
	if !authCache.invalidated {
		t.Error("expected auth cache to be invalidated")
	}

	time.Sleep(50 * time.Millisecond)
	calls := notifier.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 notify call, got %d", len(calls))
	}
	if calls[0].title != "Plan Change" {
		t.Errorf("notify title = %q, want %q", calls[0].title, "Plan Change")
	}
}

func TestHandleSubscriptionUpdated_MissingCustomerID(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, &mockNotifier{})

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{},
		},
	}

	err := svc.handleSubscriptionUpdated(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for missing customer ID")
	}
}

func TestHandleSubscriptionUpdated_UnknownPriceSkips(t *testing.T) {
	repo := &mockBillingRepo{}
	svc := newTestStripeService(repo, &mockAuthCache{}, &mockNotifier{})

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{
				"customer": "cus_123",
				"items": map[string]interface{}{
					"data": []interface{}{
						map[string]interface{}{
							"price": map[string]interface{}{
								"id": "price_unknown",
							},
						},
					},
				},
			},
		},
	}

	err := svc.handleSubscriptionUpdated(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.updatePlanCalls) != 0 {
		t.Error("expected no UpdatePlan calls for unknown price ID")
	}
}

func TestHandleSubscriptionUpdated_RepoError(t *testing.T) {
	repo := &mockBillingRepo{updatePlanErr: errors.New("db down")}
	svc := newTestStripeService(repo, &mockAuthCache{}, &mockNotifier{})

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{
				"customer": "cus_123",
				"items": map[string]interface{}{
					"data": []interface{}{
						map[string]interface{}{
							"price": map[string]interface{}{
								"id": "price_basic",
							},
						},
					},
				},
			},
		},
	}

	err := svc.handleSubscriptionUpdated(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

func TestHandleSubscriptionDeleted_HappyPath(t *testing.T) {
	repo := &mockBillingRepo{}
	authCache := &mockAuthCache{}
	notifier := &mockNotifier{}
	svc := newTestStripeService(repo, authCache, notifier)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{
				"customer": "cus_456",
			},
		},
	}

	err := svc.handleSubscriptionDeleted(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.downgradeCalls) != 1 || repo.downgradeCalls[0] != "cus_456" {
		t.Errorf("DowngradeToFree calls = %v, want [cus_456]", repo.downgradeCalls)
	}
	if !authCache.invalidated {
		t.Error("expected auth cache to be invalidated")
	}

	time.Sleep(50 * time.Millisecond)
	calls := notifier.getCalls()
	if len(calls) != 1 || calls[0].title != "Subscription Cancelled" {
		t.Errorf("notify = %v, want title %q", calls, "Subscription Cancelled")
	}
}

func TestHandleSubscriptionDeleted_MissingCustomerID(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, &mockNotifier{})

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{},
		},
	}

	err := svc.handleSubscriptionDeleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for missing customer ID")
	}
}

func TestHandlePaymentFailed_HappyPath(t *testing.T) {
	repo := &mockBillingRepo{}
	authCache := &mockAuthCache{}
	notifier := &mockNotifier{}
	svc := newTestStripeService(repo, authCache, notifier)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{
				"customer": "cus_789",
			},
		},
	}

	err := svc.handlePaymentFailed(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.downgradeCalls) != 1 || repo.downgradeCalls[0] != "cus_789" {
		t.Errorf("DowngradeToFree calls = %v, want [cus_789]", repo.downgradeCalls)
	}
	if !authCache.invalidated {
		t.Error("expected auth cache to be invalidated")
	}

	time.Sleep(50 * time.Millisecond)
	calls := notifier.getCalls()
	if len(calls) != 1 || calls[0].title != "Payment Failed" {
		t.Errorf("notify = %v, want title %q", calls, "Payment Failed")
	}
}

func TestHandlePaymentFailed_MissingCustomerID(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, &mockNotifier{})

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{},
		},
	}

	err := svc.handlePaymentFailed(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for missing customer ID")
	}
}

func TestHandlePaymentFailed_RepoError(t *testing.T) {
	repo := &mockBillingRepo{downgradeErr: errors.New("db down")}
	svc := newTestStripeService(repo, &mockAuthCache{}, &mockNotifier{})

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{
				"customer": "cus_789",
			},
		},
	}

	err := svc.handlePaymentFailed(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

func TestNewStripeService_SetsNotifier(t *testing.T) {
	n := &mockNotifier{}
	svc := NewStripeService("sk_test_123", "whsec_123", map[string]string{"price_1": "basic"}, nil, nil, n)

	if svc.notifier == nil {
		t.Fatal("notifier should not be nil")
	}
	if svc.webhookSecret != "whsec_123" {
		t.Errorf("webhookSecret = %q, want %q", svc.webhookSecret, "whsec_123")
	}
	if svc.priceToplan["price_1"] != "basic" {
		t.Errorf("priceToplan[price_1] = %q, want %q", svc.priceToplan["price_1"], "basic")
	}
}
