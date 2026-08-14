package billing

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v84"
	"go.uber.org/zap"
)

type mockNotifier struct {
	mu    sync.Mutex
	calls []notifyCall
	sent  chan struct{}
}

type notifyCall struct {
	title    string
	message  string
	priority int
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{sent: make(chan struct{}, 64)}
}

func (m *mockNotifier) Send(_ context.Context, title, message string, priority int) error {
	m.mu.Lock()
	m.calls = append(m.calls, notifyCall{title, message, priority})
	m.mu.Unlock()
	select {
	case m.sent <- struct{}{}:
	default:
	}
	return nil
}

func (m *mockNotifier) getCalls() []notifyCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]notifyCall, len(m.calls))
	copy(cp, m.calls)
	return cp
}

// waitForCalls blocks until n notifications have arrived in total, or fails the
// test on timeout. Returns the full call list.
func (m *mockNotifier) waitForCalls(t *testing.T, n int) []notifyCall {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if len(m.getCalls()) >= n {
			return m.getCalls()
		}
		select {
		case <-m.sent:
		case <-deadline:
			t.Fatalf("timed out waiting for %d notifications, got %d", n, len(m.getCalls()))
		}
	}
}

func TestStripeService_Notify(t *testing.T) {
	n := newMockNotifier()
	svc := &StripeService{notifier: n}

	svc.notify(context.Background(), "Test Title", "Test message")

	calls := n.waitForCalls(t, 1)
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
	n := newMockNotifier()
	svc := &StripeService{notifier: n}

	svc.notify(context.Background(), "New Subscriber", "user@example.com signed up for basic")
	svc.notify(context.Background(), "Subscription Canceled", "Customer cus_123 canceled")

	calls := n.waitForCalls(t, 2)
	if len(calls) != 2 {
		t.Fatalf("got %d notify calls, want 2", len(calls))
	}
}

// --- Mock types for webhook handler tests ---

type mockBillingRepo struct {
	updatePlanCalls   []struct{ customerID, plan string }
	downgradeCalls    []string
	provisionCalls    []provisionCall
	updatePlanErr     error
	downgradeErr      error
	customerExists    bool
	customerExistsErr error
	provisionErr      error
	provisionID       int
}

type provisionCall struct {
	name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey string
}

func (m *mockBillingRepo) CustomerExistsByStripeID(_ context.Context, _ string) (bool, error) {
	return m.customerExists, m.customerExistsErr
}
func (m *mockBillingRepo) ProvisionCustomer(_ context.Context, name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey string) (int, error) {
	m.provisionCalls = append(m.provisionCalls, provisionCall{name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey})
	return m.provisionID, m.provisionErr
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
		priceToplan:    map[string]string{"price_basic": "basic", "price_pro": "pro"},
		repo:           repo,
		authCache:      authCache,
		notifier:       notifier,
		generateAPIKey: func() (string, error) { return "test-generated-key-abc123", nil },
	}
}

// --- Webhook handler tests ---

func TestHandleSubscriptionUpdated_HappyPath(t *testing.T) {
	repo := &mockBillingRepo{}
	authCache := &mockAuthCache{}
	notifier := newMockNotifier()
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

	calls := notifier.waitForCalls(t, 1)
	if len(calls) != 1 {
		t.Fatalf("expected 1 notify call, got %d", len(calls))
	}
	if calls[0].title != "Plan Change" {
		t.Errorf("notify title = %q, want %q", calls[0].title, "Plan Change")
	}
}

func TestHandleSubscriptionUpdated_MissingCustomerID(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())

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
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

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
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

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
	notifier := newMockNotifier()
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

	calls := notifier.waitForCalls(t, 1)
	if len(calls) != 1 || calls[0].title != "Subscription Canceled" {
		t.Errorf("notify = %v, want title %q", calls, "Subscription Canceled")
	}
}

func TestHandleSubscriptionDeleted_MissingCustomerID(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())

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
	notifier := newMockNotifier()
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

	calls := notifier.waitForCalls(t, 1)
	if len(calls) != 1 || calls[0].title != "Payment Failed" {
		t.Errorf("notify = %v, want title %q", calls, "Payment Failed")
	}
}

func TestHandlePaymentFailed_MissingCustomerID(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())

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
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

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
	n := newMockNotifier()
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

// --- Checkout completed handler tests ---

// mockSession returns a stripe.CheckoutSession for testing.
func mockSession(id, customerID, email, name string, lineItems []*stripe.LineItem) *stripe.CheckoutSession {
	sess := &stripe.CheckoutSession{
		ID: id,
		Customer: &stripe.Customer{
			ID: customerID,
		},
		CustomerDetails: &stripe.CheckoutSessionCustomerDetails{
			Email: email,
			Name:  name,
		},
	}
	if lineItems != nil {
		sess.LineItems = &stripe.LineItemList{
			Data: lineItems,
		}
	}
	return sess
}

func newCheckoutTestService(repo *mockBillingRepo, sess, expandedSess *stripe.CheckoutSession) *StripeService {
	callCount := 0
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())
	svc.fetchSession = func(_ string, _ *stripe.CheckoutSessionParams) (*stripe.CheckoutSession, error) {
		callCount++
		if callCount == 1 {
			return sess, nil
		}
		return expandedSess, nil
	}
	return svc
}

func TestHandleCheckoutCompleted_HappyPath(t *testing.T) {
	repo := &mockBillingRepo{provisionID: 99}
	sess := mockSession("cs_123", "cus_abc", "user@example.com", "Jane Doe", nil)
	expanded := mockSession("cs_123", "cus_abc", "user@example.com", "Jane Doe",
		[]*stripe.LineItem{{Price: &stripe.Price{ID: "price_pro"}}},
	)
	svc := newCheckoutTestService(repo, sess, expanded)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.provisionCalls) != 1 {
		t.Fatalf("expected 1 ProvisionCustomer call, got %d", len(repo.provisionCalls))
	}
	call := repo.provisionCalls[0]
	if call.name != "Jane Doe" {
		t.Errorf("name = %q, want %q", call.name, "Jane Doe")
	}
	if call.email != "user@example.com" {
		t.Errorf("email = %q, want %q", call.email, "user@example.com")
	}
	if call.plan != "pro" {
		t.Errorf("plan = %q, want %q", call.plan, "pro")
	}
	if call.stripeCustomerID != "cus_abc" {
		t.Errorf("stripeCustomerID = %q, want %q", call.stripeCustomerID, "cus_abc")
	}
}

func TestHandleCheckoutCompleted_UsesEmailAsNameWhenEmpty(t *testing.T) {
	repo := &mockBillingRepo{provisionID: 1}
	sess := mockSession("cs_123", "cus_abc", "user@example.com", "", nil)
	expanded := mockSession("cs_123", "cus_abc", "user@example.com", "",
		[]*stripe.LineItem{{Price: &stripe.Price{ID: "price_basic"}}},
	)
	svc := newCheckoutTestService(repo, sess, expanded)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.provisionCalls[0].name != "user@example.com" {
		t.Errorf("name = %q, want email fallback %q", repo.provisionCalls[0].name, "user@example.com")
	}
}

func TestHandleCheckoutCompleted_IdempotentForExistingCustomer(t *testing.T) {
	repo := &mockBillingRepo{customerExists: true}
	sess := mockSession("cs_123", "cus_abc", "user@example.com", "Jane", nil)
	svc := newCheckoutTestService(repo, sess, nil)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.provisionCalls) != 0 {
		t.Error("expected no ProvisionCustomer calls for existing customer")
	}
}

func TestHandleCheckoutCompleted_NilCustomer_ReturnsError(t *testing.T) {
	sess := &stripe.CheckoutSession{ID: "cs_123", Customer: nil}
	svc := newCheckoutTestService(&mockBillingRepo{}, sess, nil)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for nil customer")
	}
	if !strings.Contains(err.Error(), "no customer") {
		t.Errorf("error = %q, want to contain 'no customer'", err.Error())
	}
}

func TestHandleCheckoutCompleted_NilCustomerDetails_ReturnsError(t *testing.T) {
	sess := &stripe.CheckoutSession{
		ID:       "cs_123",
		Customer: &stripe.Customer{ID: "cus_abc"},
	}
	svc := newCheckoutTestService(&mockBillingRepo{}, sess, nil)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for nil customer details")
	}
	if !strings.Contains(err.Error(), "no customer details") {
		t.Errorf("error = %q, want to contain 'no customer details'", err.Error())
	}
}

func TestHandleCheckoutCompleted_UnmatchedPriceID_ReturnsError(t *testing.T) {
	repo := &mockBillingRepo{}
	sess := mockSession("cs_123", "cus_abc", "user@example.com", "Jane", nil)
	expanded := mockSession("cs_123", "cus_abc", "user@example.com", "Jane",
		[]*stripe.LineItem{{Price: &stripe.Price{ID: "price_unknown"}}},
	)
	svc := newCheckoutTestService(repo, sess, expanded)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for unmatched price ID")
	}
	if !strings.Contains(err.Error(), "no matching price ID") {
		t.Errorf("error = %q, want to contain 'no matching price ID'", err.Error())
	}
	if len(repo.provisionCalls) != 0 {
		t.Error("expected no ProvisionCustomer calls when plan determination fails")
	}
}

func TestHandleCheckoutCompleted_ProvisionError_ReturnsError(t *testing.T) {
	repo := &mockBillingRepo{provisionErr: errors.New("db down")}
	sess := mockSession("cs_123", "cus_abc", "user@example.com", "Jane", nil)
	expanded := mockSession("cs_123", "cus_abc", "user@example.com", "Jane",
		[]*stripe.LineItem{{Price: &stripe.Price{ID: "price_basic"}}},
	)
	svc := newCheckoutTestService(repo, sess, expanded)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error from provision failure")
	}
	if !strings.Contains(err.Error(), "provision customer") {
		t.Errorf("error = %q, want to contain 'provision customer'", err.Error())
	}
}

func TestHandleCheckoutCompleted_CustomerExistsCheckError_ReturnsError(t *testing.T) {
	repo := &mockBillingRepo{customerExistsErr: errors.New("db down")}
	sess := mockSession("cs_123", "cus_abc", "user@example.com", "Jane", nil)
	svc := newCheckoutTestService(repo, sess, nil)

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error from customer exists check")
	}
	if !strings.Contains(err.Error(), "check existing customer") {
		t.Errorf("error = %q, want to contain 'check existing customer'", err.Error())
	}
}

func TestHandleCheckoutCompleted_SessionFetchError_ReturnsError(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())
	svc.fetchSession = func(string, *stripe.CheckoutSessionParams) (*stripe.CheckoutSession, error) {
		return nil, errors.New("stripe unavailable")
	}

	event := &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]any{"id": "cs_123"},
		},
	}

	err := svc.handleCheckoutCompleted(context.Background(), event, zap.NewNop())
	if err == nil {
		t.Fatal("expected error from session fetch failure")
	}
	if !strings.Contains(err.Error(), "retrieve checkout session") {
		t.Errorf("error = %q, want to contain 'retrieve checkout session'", err.Error())
	}
}

// --- GetProvisionedKey ---

type retrievingRepo struct {
	mockBillingRepo
	key string
	err error
}

func (r *retrievingRepo) RetrieveProvisionedKey(_ context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return "", errors.New("empty session id")
	}
	return r.key, r.err
}

func TestGetProvisionedKey_ReturnsRepoResult(t *testing.T) {
	repo := &retrievingRepo{key: "raw_secret_key"}
	svc := newTestStripeService(&repo.mockBillingRepo, &mockAuthCache{}, newMockNotifier())
	svc.repo = repo

	key, err := svc.GetProvisionedKey(context.Background(), "cs_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "raw_secret_key" {
		t.Errorf("key = %q, want %q", key, "raw_secret_key")
	}
}

func TestGetProvisionedKey_PropagatesRepoError(t *testing.T) {
	repo := &retrievingRepo{err: ErrKeyRetrieved}
	svc := newTestStripeService(&repo.mockBillingRepo, &mockAuthCache{}, newMockNotifier())
	svc.repo = repo

	_, err := svc.GetProvisionedKey(context.Background(), "cs_123")
	if !errors.Is(err, ErrKeyRetrieved) {
		t.Errorf("err = %v, want ErrKeyRetrieved", err)
	}
}
