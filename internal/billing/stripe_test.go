package billing

import (
	"context"
	"errors"
	"fmt"
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
	svc.notify(context.Background(), "Subscription Cancelled", "Customer cus_123 cancelled")

	calls := n.waitForCalls(t, 2)
	if len(calls) != 2 {
		t.Fatalf("got %d notify calls, want 2", len(calls))
	}
}

// --- Mock types for webhook handler tests ---

type provisionCall struct {
	name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey string
}

type mockBillingRepo struct {
	updatePlanCalls []struct{ customerID, plan string }
	downgradeCalls  []string
	updatePlanErr   error
	downgradeErr    error

	// Checkout-flow fields.
	existsByID         map[string]bool
	existsByIDErr      error
	provisionCalls     []provisionCall
	provisionCustomerID int
	provisionErr       error
}

func (m *mockBillingRepo) CustomerExistsByStripeID(_ context.Context, id string) (bool, error) {
	if m.existsByIDErr != nil {
		return false, m.existsByIDErr
	}
	return m.existsByID[id], nil
}
func (m *mockBillingRepo) ProvisionCustomer(_ context.Context, name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey string) (int, error) {
	m.provisionCalls = append(m.provisionCalls, provisionCall{name, email, plan, stripeCustomerID, keyHash, sessionID, rawKey})
	if m.provisionErr != nil {
		return 0, m.provisionErr
	}
	return m.provisionCustomerID, nil
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
	if len(calls) != 1 || calls[0].title != "Subscription Cancelled" {
		t.Errorf("notify = %v, want title %q", calls, "Subscription Cancelled")
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
	if svc.getSession == nil {
		t.Error("getSession should default to the real Stripe SDK fetcher")
	}
}

// --- Checkout webhook tests ---

func checkoutEvent(sessionID string) *stripe.Event {
	return &stripe.Event{
		Data: &stripe.EventData{
			Object: map[string]interface{}{"id": sessionID},
		},
	}
}

// stubGetSession returns a getSession func that serves canned sessions keyed by
// session ID. The bool indicates whether line_items expansion was requested.
// callsByExpansion records each call so tests can verify both fetches happened.
func stubGetSession(sessions map[string]*stripe.CheckoutSession, callsByExpansion *[]bool) func(context.Context, string, bool) (*stripe.CheckoutSession, error) {
	return func(_ context.Context, sessionID string, expand bool) (*stripe.CheckoutSession, error) {
		if callsByExpansion != nil {
			*callsByExpansion = append(*callsByExpansion, expand)
		}
		sess, ok := sessions[sessionID]
		if !ok {
			return nil, fmt.Errorf("stub: session %q not found", sessionID)
		}
		// Mimic Stripe: line_items only populated when expanded.
		if !expand {
			cp := *sess
			cp.LineItems = nil
			return &cp, nil
		}
		return sess, nil
	}
}

func TestHandleCheckoutCompleted_HappyPath(t *testing.T) {
	repo := &mockBillingRepo{provisionCustomerID: 42}
	authCache := &mockAuthCache{}
	notifier := newMockNotifier()
	svc := newTestStripeService(repo, authCache, notifier)

	var calls []bool
	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_123": {
			ID:       "cs_123",
			Customer: &stripe.Customer{ID: "cus_abc"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{
				Email: "buyer@example.com",
				Name:  "Buyer Name",
			},
			LineItems: &stripe.LineItemList{
				Data: []*stripe.LineItem{
					{Price: &stripe.Price{ID: "price_pro"}},
				},
			},
		},
	}, &calls)

	if err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_123"), zap.NewNop()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 2 || calls[0] != false || calls[1] != true {
		t.Errorf("expected two getSession calls (no-expand, then expand), got %v", calls)
	}
	if len(repo.provisionCalls) != 1 {
		t.Fatalf("expected 1 ProvisionCustomer call, got %d", len(repo.provisionCalls))
	}
	pc := repo.provisionCalls[0]
	if pc.plan != "pro" {
		t.Errorf("plan = %q, want %q", pc.plan, "pro")
	}
	if pc.stripeCustomerID != "cus_abc" {
		t.Errorf("stripeCustomerID = %q, want %q", pc.stripeCustomerID, "cus_abc")
	}
	if pc.email != "buyer@example.com" {
		t.Errorf("email = %q, want %q", pc.email, "buyer@example.com")
	}
	if pc.name != "Buyer Name" {
		t.Errorf("name = %q, want %q", pc.name, "Buyer Name")
	}
	if pc.sessionID != "cs_123" {
		t.Errorf("sessionID = %q, want %q", pc.sessionID, "cs_123")
	}
	if pc.rawKey == "" || pc.keyHash == "" {
		t.Error("expected ProvisionCustomer to receive a generated rawKey and keyHash")
	}
	if pc.rawKey == pc.keyHash {
		t.Error("rawKey and keyHash should differ (hash should not equal plaintext)")
	}

	calls2 := notifier.waitForCalls(t, 1)
	if calls2[0].title != "New Subscriber" {
		t.Errorf("notify title = %q, want %q", calls2[0].title, "New Subscriber")
	}
}

func TestHandleCheckoutCompleted_FallsBackToEmailWhenNameMissing(t *testing.T) {
	repo := &mockBillingRepo{}
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_noname": {
			ID:       "cs_noname",
			Customer: &stripe.Customer{ID: "cus_noname"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{
				Email: "noname@example.com",
			},
			LineItems: &stripe.LineItemList{
				Data: []*stripe.LineItem{{Price: &stripe.Price{ID: "price_basic"}}},
			},
		},
	}, nil)

	if err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_noname"), zap.NewNop()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.provisionCalls) != 1 {
		t.Fatalf("expected 1 ProvisionCustomer call, got %d", len(repo.provisionCalls))
	}
	if repo.provisionCalls[0].name != "noname@example.com" {
		t.Errorf("name = %q, want fallback to email %q", repo.provisionCalls[0].name, "noname@example.com")
	}
}

func TestHandleCheckoutCompleted_ExistingCustomer_Idempotent(t *testing.T) {
	repo := &mockBillingRepo{
		existsByID: map[string]bool{"cus_already": true},
	}
	notifier := newMockNotifier()
	svc := newTestStripeService(repo, &mockAuthCache{}, notifier)

	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_dup": {
			ID:       "cs_dup",
			Customer: &stripe.Customer{ID: "cus_already"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{
				Email: "dup@example.com",
			},
			LineItems: &stripe.LineItemList{
				Data: []*stripe.LineItem{{Price: &stripe.Price{ID: "price_pro"}}},
			},
		},
	}, nil)

	if err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_dup"), zap.NewNop()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repo.provisionCalls) != 0 {
		t.Errorf("expected no ProvisionCustomer call for existing customer, got %d", len(repo.provisionCalls))
	}
	// No notification should fire for a duplicate webhook.
	if got := len(notifier.getCalls()); got != 0 {
		t.Errorf("expected no notifications for duplicate, got %d", got)
	}
}

func TestHandleCheckoutCompleted_UnknownPriceReturnsError(t *testing.T) {
	repo := &mockBillingRepo{}
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_unk": {
			ID:       "cs_unk",
			Customer: &stripe.Customer{ID: "cus_unk"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{Email: "x@example.com"},
			LineItems: &stripe.LineItemList{
				Data: []*stripe.LineItem{{Price: &stripe.Price{ID: "price_NOT_MAPPED"}}},
			},
		},
	}, nil)

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_unk"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error for unknown price ID, got nil")
	}
	if !strings.Contains(err.Error(), "no matching price ID") {
		t.Errorf("error = %v, want it to mention missing price ID", err)
	}
	if len(repo.provisionCalls) != 0 {
		t.Errorf("expected no ProvisionCustomer call when plan is undeterminable, got %d", len(repo.provisionCalls))
	}
}

func TestHandleCheckoutCompleted_EmptyLineItemsReturnsError(t *testing.T) {
	repo := &mockBillingRepo{}
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_empty": {
			ID:              "cs_empty",
			Customer:        &stripe.Customer{ID: "cus_empty"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{Email: "x@example.com"},
			LineItems:       &stripe.LineItemList{Data: nil},
		},
	}, nil)

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_empty"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error when line items are empty")
	}
}

func TestHandleCheckoutCompleted_ProvisionFailureReturnsError(t *testing.T) {
	repo := &mockBillingRepo{provisionErr: errors.New("db unavailable")}
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_dberr": {
			ID:              "cs_dberr",
			Customer:        &stripe.Customer{ID: "cus_dberr"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{Email: "x@example.com"},
			LineItems: &stripe.LineItemList{
				Data: []*stripe.LineItem{{Price: &stripe.Price{ID: "price_pro"}}},
			},
		},
	}, nil)

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_dberr"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error from provision failure")
	}
}

func TestHandleCheckoutCompleted_ExistsCheckErrorReturnsError(t *testing.T) {
	repo := &mockBillingRepo{existsByIDErr: errors.New("db down")}
	svc := newTestStripeService(repo, &mockAuthCache{}, newMockNotifier())

	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_x": {
			ID:              "cs_x",
			Customer:        &stripe.Customer{ID: "cus_x"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{Email: "x@example.com"},
		},
	}, nil)

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_x"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error from CustomerExistsByStripeID failure")
	}
}

func TestHandleCheckoutCompleted_FirstSessionFetchErrorReturnsError(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())
	svc.getSession = func(context.Context, string, bool) (*stripe.CheckoutSession, error) {
		return nil, errors.New("stripe down")
	}

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_anything"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error from session fetch failure")
	}
}

func TestHandleCheckoutCompleted_ExpansionFetchErrorReturnsError(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())
	svc.getSession = func(_ context.Context, _ string, expand bool) (*stripe.CheckoutSession, error) {
		if expand {
			return nil, errors.New("expansion failed")
		}
		return &stripe.CheckoutSession{
			ID:              "cs_exp",
			Customer:        &stripe.Customer{ID: "cus_exp"},
			CustomerDetails: &stripe.CheckoutSessionCustomerDetails{Email: "x@example.com"},
		}, nil
	}

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_exp"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error from line-items fetch failure")
	}
}

func TestHandleCheckoutCompleted_MissingCustomerReturnsError(t *testing.T) {
	svc := newTestStripeService(&mockBillingRepo{}, &mockAuthCache{}, newMockNotifier())
	svc.getSession = stubGetSession(map[string]*stripe.CheckoutSession{
		"cs_nocust": {ID: "cs_nocust"},
	}, nil)

	err := svc.handleCheckoutCompleted(context.Background(), checkoutEvent("cs_nocust"), zap.NewNop())
	if err == nil {
		t.Fatal("expected error when checkout session has no customer")
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
