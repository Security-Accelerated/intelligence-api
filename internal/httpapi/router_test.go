package httpapi

import (
	"strings"
	"testing"

	"github.com/security-accelerated/intelligence-api/internal/middleware"
)

func TestRouterDeps_Validate(t *testing.T) {
	tests := []struct {
		name           string
		clientIPHeader string
		origin         middleware.OriginConfig
		wantErr        string
	}{
		{
			name:           "shipped defaults",
			clientIPHeader: FlyClientIPHeader,
		},
		{
			name:           "secret staged, enforcement still off",
			clientIPHeader: FlyClientIPHeader,
			origin:         middleware.OriginConfig{Header: "X-Origin-Secret", Secret: "s3cret"},
		},
		{
			name:           "cutover: both flipped together",
			clientIPHeader: "CF-Connecting-IP",
			origin:         middleware.OriginConfig{Header: "X-Origin-Secret", Secret: "s3cret", Require: true},
		},
		{
			name:           "enforcement on, no secret",
			clientIPHeader: FlyClientIPHeader,
			origin:         middleware.OriginConfig{Header: "X-Origin-Secret", Require: true},
			wantErr:        "edge.origin_secret is empty",
		},
		{
			name:           "enforcement on, no header name",
			clientIPHeader: FlyClientIPHeader,
			origin:         middleware.OriginConfig{Secret: "s3cret", Require: true},
			wantErr:        "edge.origin_secret_header is empty",
		},
		{
			// The combination the interlock exists for: trusting a header the
			// edge sets while the origin is still reachable directly.
			name:           "edge header trusted with the origin open",
			clientIPHeader: "CF-Connecting-IP",
			origin:         middleware.OriginConfig{Header: "X-Origin-Secret", Secret: "s3cret"},
			wantErr:        "could forge its own client IP",
		},
		{
			name:           "blanked client IP header without enforcement",
			clientIPHeader: "",
			wantErr:        "could forge its own client IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := RouterDeps{
				Mode:           "development",
				BodyLimit:      1 << 20,
				ClientIPHeader: tt.clientIPHeader,
				Origin:         tt.origin,
			}

			err := d.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// NewRouter must refuse to build rather than serve an unsafe configuration.
func TestNewRouter_RejectsInvalidEdgeConfig(t *testing.T) {
	_, err := NewRouter(RouterDeps{
		Mode:           "production",
		BodyLimit:      1 << 20,
		ClientIPHeader: "CF-Connecting-IP",
	})
	if err == nil {
		t.Fatal("NewRouter() = nil error, want a startup failure")
	}
	if !strings.Contains(err.Error(), "router config") {
		t.Errorf("error = %q, want it wrapped with %q", err.Error(), "router config")
	}
}
