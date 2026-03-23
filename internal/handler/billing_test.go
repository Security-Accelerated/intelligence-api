package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type mockBillingService struct {
	webhookErr      error
	provisionedKey  string
	provisionedErr  error
	lastPayload     []byte
	lastSigHeader   string
	lastSessionID   string
}

func (m *mockBillingService) HandleWebhook(_ context.Context, payload []byte, sigHeader string) error {
	m.lastPayload = payload
	m.lastSigHeader = sigHeader
	return m.webhookErr
}

func (m *mockBillingService) GetProvisionedKey(_ context.Context, sessionID string) (string, error) {
	m.lastSessionID = sessionID
	return m.provisionedKey, m.provisionedErr
}

func newBillingTestRouter(billingSvc *mockBillingService, cfg *viper.Viper) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := New(nil, nil, billingSvc, nil, cfg, nil, nil, nil, nil)
	h.RegisterRoutes(r)
	return r
}

func TestStripeWebhook_MissingSignature(t *testing.T) {
	r := newBillingTestRouter(&mockBillingService{}, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", strings.NewReader(`{}`))
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "missing Stripe-Signature") {
		t.Errorf("body = %q, want mention of missing signature", w.Body.String())
	}
}

func TestStripeWebhook_ServiceError(t *testing.T) {
	svc := &mockBillingService{webhookErr: errors.New("bad signature")}
	r := newBillingTestRouter(svc, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", strings.NewReader(`{"type":"test"}`))
	req.Header.Set("Stripe-Signature", "t=123,v1=abc")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if svc.lastSigHeader != "t=123,v1=abc" {
		t.Errorf("sig header = %q, want %q", svc.lastSigHeader, "t=123,v1=abc")
	}
}

func TestStripeWebhook_Success(t *testing.T) {
	svc := &mockBillingService{}
	r := newBillingTestRouter(svc, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/billing/webhook", strings.NewReader(`{"type":"checkout.session.completed"}`))
	req.Header.Set("Stripe-Signature", "t=123,v1=abc")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "received") {
		t.Errorf("body = %q, want 'received'", w.Body.String())
	}
}

func TestCheckoutSuccess_MissingSessionID(t *testing.T) {
	r := newBillingTestRouter(&mockBillingService{}, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Missing session ID") {
		t.Errorf("body should mention missing session ID, got %q", body[:min(len(body), 200)])
	}
}

func TestCheckoutSuccess_KeyRetrieved(t *testing.T) {
	svc := &mockBillingService{
		provisionedKey: "abc123def456",
	}
	r := newBillingTestRouter(svc, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test_123", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "abc123def456") {
		t.Error("expected body to contain the API key")
	}
	if !strings.Contains(body, "Save this key now") {
		t.Error("expected body to contain save warning")
	}
	if svc.lastSessionID != "cs_test_123" {
		t.Errorf("session ID = %q, want %q", svc.lastSessionID, "cs_test_123")
	}
}

func TestCheckoutSuccess_KeyAlreadyRetrieved(t *testing.T) {
	svc := &mockBillingService{
		provisionedErr: errors.New("key has already been retrieved"),
	}
	r := newBillingTestRouter(svc, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test_123", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "already been retrieved") {
		t.Errorf("expected body to mention key already retrieved, got %q", body[:min(len(body), 200)])
	}
}

func TestCheckoutSuccess_NoStoreHeader(t *testing.T) {
	svc := &mockBillingService{provisionedKey: "testkey123"}
	r := newBillingTestRouter(svc, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test_123", nil)
	r.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
}

func TestCheckoutSuccess_PortalLinkShown(t *testing.T) {
	svc := &mockBillingService{provisionedKey: "testkey123"}
	cfg := viper.New()
	cfg.Set("stripe.portal_link", "https://billing.stripe.com/p/login/test_abc")
	r := newBillingTestRouter(svc, cfg)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test_123", nil)
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Manage subscription") {
		t.Error("expected body to contain 'Manage subscription' link")
	}
	if !strings.Contains(body, "https://billing.stripe.com/p/login/test_abc") {
		t.Error("expected body to contain portal link URL")
	}
}

func TestCheckoutSuccess_PortalLinkHiddenWhenEmpty(t *testing.T) {
	svc := &mockBillingService{provisionedKey: "testkey123"}
	r := newBillingTestRouter(svc, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/billing/success?session_id=cs_test_123", nil)
	r.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "Manage subscription") {
		t.Error("portal link should be hidden when not configured")
	}
}
