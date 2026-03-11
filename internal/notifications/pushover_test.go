package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPushoverNotifier_Send(t *testing.T) {
	var gotToken, gotUser, gotTitle, gotMessage, gotPriority string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		gotToken = r.FormValue("token")
		gotUser = r.FormValue("user")
		gotTitle = r.FormValue("title")
		gotMessage = r.FormValue("message")
		gotPriority = r.FormValue("priority")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := &PushoverNotifier{
		apiToken: "tok_abc",
		userKey:  "usr_123",
		client:   srv.Client(),
		endpoint: srv.URL,
	}

	err := p.Send(context.Background(), "Test Alert", "something broke", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotToken != "tok_abc" {
		t.Errorf("token = %q, want %q", gotToken, "tok_abc")
	}
	if gotUser != "usr_123" {
		t.Errorf("user = %q, want %q", gotUser, "usr_123")
	}
	if gotTitle != "Test Alert" {
		t.Errorf("title = %q, want %q", gotTitle, "Test Alert")
	}
	if gotMessage != "something broke" {
		t.Errorf("message = %q, want %q", gotMessage, "something broke")
	}
	if gotPriority != "1" {
		t.Errorf("priority = %q, want %q", gotPriority, "1")
	}
}

func TestPushoverNotifier_Send_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	p := &PushoverNotifier{
		apiToken: "tok",
		userKey:  "usr",
		client:   srv.Client(),
		endpoint: srv.URL,
	}

	err := p.Send(context.Background(), "title", "msg", 0)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestNoopNotifier_Send(t *testing.T) {
	n := &NoopNotifier{}
	if err := n.Send(context.Background(), "title", "msg", 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
