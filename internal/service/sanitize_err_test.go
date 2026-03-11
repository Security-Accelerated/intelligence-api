package service

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

func TestSanitizeErr_BlockedError(t *testing.T) {
	err := &safenet.BlockedError{IP: net.ParseIP("127.0.0.1")}
	got := sanitizeErr(err)
	want := "domain resolves to a private/reserved IP address"
	if got != want {
		t.Errorf("sanitizeErr(BlockedError) = %q, want %q", got, want)
	}
}

func TestSanitizeErr_WrappedBlockedError(t *testing.T) {
	inner := &safenet.BlockedError{IP: net.ParseIP("10.0.0.1")}
	wrapped := errors.Join(errors.New("dial failed"), inner)
	got := sanitizeErr(wrapped)
	want := "domain resolves to a private/reserved IP address"
	if got != want {
		t.Errorf("sanitizeErr(wrapped BlockedError) = %q, want %q", got, want)
	}
}

func TestSanitizeErr_ColonStripping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "single colon",
			err:  errors.New("whois: connection refused"),
			want: "connection refused",
		},
		{
			name: "nested colons strips to last segment",
			err:  errors.New("lookup: whois: dial tcp: connection refused"),
			want: "connection refused",
		},
		{
			name: "no colon passes through",
			err:  errors.New("something went wrong"),
			want: "something went wrong",
		},
		{
			name: "colon at end",
			err:  errors.New("error: "),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeErr(tt.err)
			if got != tt.want {
				t.Errorf("sanitizeErr(%q) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestSanitizeErr_BlockedErrorTakesPrecedence(t *testing.T) {
	// Even if the error message contains colons, BlockedError should match first.
	inner := &safenet.BlockedError{IP: net.ParseIP("192.168.1.1")}
	wrapped := fmt.Errorf("lookup: headers: %w", inner)
	got := sanitizeErr(wrapped)
	want := "domain resolves to a private/reserved IP address"
	if got != want {
		t.Errorf("sanitizeErr(wrapped with colons) = %q, want %q", got, want)
	}
}
