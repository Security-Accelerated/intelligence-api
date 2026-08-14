package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotFound_HTMLPageForBrowserPaths(t *testing.T) {
	for _, path := range []string{"/nope", "/docs/nope", "/docs/domain/extra"} {
		t.Run(path, func(t *testing.T) {
			r := docsRouter()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, http.NoBody))

			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", ct)
			}
			if got := w.Header().Get("Content-Security-Policy"); got != htmlPageCSP {
				t.Errorf("Content-Security-Policy = %q, want the HTML page policy", got)
			}

			body := w.Body.String()
			// A 404 is a dead end unless it offers a way out.
			for _, link := range []string{`href="/docs"`, `href="/docs/domain"`, `href="/docs/ip"`} {
				if !strings.Contains(body, link) {
					t.Errorf("404 page does not link to %s", link)
				}
			}
			if strings.Contains(body, "<script>") || strings.Contains(body, "onclick=") {
				t.Error("404 page must not carry inline script, same as every other page")
			}
		})
	}
}

// TestNotFound_JSONForAPIPaths covers the case a customer actually hits: a
// typo in an endpoint path. Returning HTML there would break a caller's error
// handling on a response it is otherwise equipped to parse.
func TestNotFound_JSONForAPIPaths(t *testing.T) {
	for _, path := range []string{
		"/v1/nope",
		"/v1/domain/looku",
		"/v1/domain/lookup/extra",
		"/billing/nope",
	} {
		t.Run(path, func(t *testing.T) {
			r := docsRouter()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, http.NoBody))

			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}

			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if body["error"] != "not found" {
				t.Errorf("error = %q, want %q", body["error"], "not found")
			}
			if len(body) != 1 {
				t.Errorf("body = %v, want only an error field", body)
			}
		})
	}
}

// TestNotFound_DoesNotEchoRequestedPath guards the decision not to reflect
// caller-chosen text onto our own domain, which would turn the 404 into a
// place to host arbitrary wording under securityaccelerated.com.
func TestNotFound_DoesNotEchoRequestedPath(t *testing.T) {
	const marker = "call-1-800-not-us-to-reactivate"

	r := docsRouter()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+marker, http.NoBody))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if strings.Contains(w.Body.String(), marker) {
		t.Error("404 page echoed the requested path back to the caller")
	}
}

// TestNotFound_KnownRoutesUnaffected is the other half of registering a
// catch-all: a NoRoute handler that shadowed a real route would be invisible
// until someone hit it in production.
func TestNotFound_KnownRoutesUnaffected(t *testing.T) {
	r := docsRouter()

	for _, path := range append([]string{"/docs/styles.css", "/docs/openapi.yaml"}, docsPagePaths...) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, http.NoBody))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, w.Code)
		}
	}
}

func TestIsAPIPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/v1/domain/lookup": true,
		"/v1/":              true,
		"/v1":               true,
		"/billing/webhook":  true,
		"/billing":          true,
		"/v1x/lookup":       false,
		"/docs":             false,
		"/docs/v1/lookup":   false,
		"/":                 false,
	} {
		if got := isAPIPath(path); got != want {
			t.Errorf("isAPIPath(%q) = %v, want %v", path, got, want)
		}
	}
}
