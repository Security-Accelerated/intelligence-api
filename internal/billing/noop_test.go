package billing

import (
	"context"
	"testing"
)

func TestNoopService_HandleWebhook(t *testing.T) {
	svc := &NoopService{}
	err := svc.HandleWebhook(context.Background(), nil, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err != errNotConfigured {
		t.Errorf("error = %v, want %v", err, errNotConfigured)
	}
}

func TestNoopService_GetProvisionedKey(t *testing.T) {
	svc := &NoopService{}
	key, err := svc.GetProvisionedKey(context.Background(), "sess_123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err != errNotConfigured {
		t.Errorf("error = %v, want %v", err, errNotConfigured)
	}
	if key != "" {
		t.Errorf("key = %q, want empty", key)
	}
}
