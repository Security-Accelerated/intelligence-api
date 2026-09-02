package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func setupOriginRouter(cfg OriginConfig) (*gin.Engine, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(OriginSecretWithLogger(cfg, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r, logs
}

func doOriginRequest(r *gin.Engine, header, value string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	if header != "" {
		req.Header.Set(header, value)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestOriginSecret_DisabledPassesThrough(t *testing.T) {
	// The shipped default: no secret, no enforcement, nothing rejected.
	r, logs := setupOriginRouter(OriginConfig{Header: "X-Origin-Secret"})

	w := doOriginRequest(r, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if logs.Len() != 0 {
		t.Errorf("expected no logs, got %d", logs.Len())
	}
}

func TestOriginSecret_Enforcement(t *testing.T) {
	cfg := OriginConfig{Header: "X-Origin-Secret", Secret: "s3cret", Require: true}

	tests := []struct {
		name       string
		header     string
		value      string
		wantStatus int
	}{
		{"correct secret", "X-Origin-Secret", "s3cret", http.StatusOK},
		{"missing header", "", "", http.StatusForbidden},
		{"empty value", "X-Origin-Secret", "", http.StatusForbidden},
		{"wrong value", "X-Origin-Secret", "wrong!", http.StatusForbidden},
		// Same length as the secret: a compare that bailed on length alone
		// would still reject this, but it is the case a timing attack probes.
		{"same length, wrong", "X-Origin-Secret", "s3cres", http.StatusForbidden},
		{"prefix of secret", "X-Origin-Secret", "s3cre", http.StatusForbidden},
		{"secret plus suffix", "X-Origin-Secret", "s3cretx", http.StatusForbidden},
		{"right value, wrong header", "X-Other-Secret", "s3cret", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, logs := setupOriginRouter(cfg)

			w := doOriginRequest(r, tt.header, tt.value)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK {
				if logs.Len() != 0 {
					t.Errorf("expected no logs on success, got %d", logs.Len())
				}
				return
			}

			// The body must not hint that the secret is what was missing.
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if body["error"] != "forbidden" {
				t.Errorf("error = %q, want %q", body["error"], "forbidden")
			}

			if logs.Len() == 0 {
				t.Fatal("expected warn log")
			}
			if got := logs.All()[0].Message; got != "origin secret rejected" {
				t.Errorf("log message = %q, want %q", got, "origin secret rejected")
			}
		})
	}
}

// The rejection log must never carry the secret, in either direction.
func TestOriginSecret_DoesNotLogSecret(t *testing.T) {
	r, logs := setupOriginRouter(OriginConfig{
		Header:  "X-Origin-Secret",
		Secret:  "s3cret",
		Require: true,
	})

	doOriginRequest(r, "X-Origin-Secret", "attacker-guess")

	if logs.Len() == 0 {
		t.Fatal("expected warn log")
	}
	for _, entry := range logs.All() {
		for _, f := range entry.Context {
			if f.String == "s3cret" || f.String == "attacker-guess" {
				t.Errorf("log field %q leaked a secret value: %q", f.Key, f.String)
			}
		}
	}
}
