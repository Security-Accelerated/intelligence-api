package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// allSitePages adds the company page to the docs pages for the one docs rule
// that applies to it: docs.js runs there too, so the controls it injects must
// not be written into the markup. The docs nav and table rules do not apply;
// the home page has its own nav and no tables.
func allSitePages() []docsPage {
	return append(allDocsHTML(), docsPage{Path: "/", HTML: homeHTML, Tmpl: homeTmpl})
}

func getHome(t *testing.T, cfg *viper.Viper) string {
	t.Helper()
	r := docsRouterWithData(nil, cfg, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	// The API-wide CSP is default-src 'none'; without the page override the
	// stylesheets, the fonts and the scripts are blocked and the page renders
	// unstyled.
	if got := w.Header().Get("Content-Security-Policy"); got != htmlPageCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", got, htmlPageCSP)
	}
	return w.Body.String()
}

// The root used to be a 301 to /docs. It now answers for the company, and the
// docs have to stay one link away from it.
func TestHome_ServesCompanyPage(t *testing.T) {
	body := getHome(t, nil)

	for _, want := range []string{
		"<title>Security Accelerated</title>",
		`href="/docs"`,
		`href="/docs/domain"`,
		`href="/docs/ip"`,
		"mailto:support@securityaccelerated.com",
		`<link rel="stylesheet" href="/docs/styles.css">`,
		`<script src="/docs/theme.js"></script>`,
		`<script src="/docs/docs.js" defer></script>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("home page does not contain %q", want)
		}
	}

	// Blocked silently by the CSP, so nothing but this test would notice.
	if strings.Contains(body, "<script>") || strings.Contains(body, "onclick=") {
		t.Error("home page must not contain inline scripts or event handlers")
	}
}

// The section nav is in-page anchors. A renamed section id leaves a nav item
// that scrolls nowhere, which no other test would catch.
func TestHome_SectionLinksResolve(t *testing.T) {
	anchors := regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(homeHTML, -1)
	if len(anchors) == 0 {
		t.Fatal("home page has no in-page links; the section nav is gone")
	}
	for _, m := range anchors {
		if !strings.Contains(homeHTML, `id="`+m[1]+`"`) {
			t.Errorf("link to #%s has no element with that id", m[1])
		}
	}
}

// The home page shows the same price and payment link as the Plans table on
// /docs, from the same config keys, so the two cannot quote different prices.
func TestHome_PlansFollowBillingConfig(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		cfg := viper.New()
		cfg.Set("stripe.payment_link.pro", "https://buy.stripe.com/test_pro")
		cfg.Set("stripe.price_display.pro", "$29/month")
		body := getHome(t, cfg)

		if !strings.Contains(body, `href="https://buy.stripe.com/test_pro"`) {
			t.Error("expected the pro payment link")
		}
		if !strings.Contains(body, `<p class="home-price">$29/month</p>`) {
			t.Error("expected the pro price on the Pro plan")
		}
	})

	t.Run("unconfigured", func(t *testing.T) {
		body := getHome(t, nil)

		if !strings.Contains(body, "Contact us for a Pro key.") {
			t.Error("expected the contact fallback when no payment link is configured")
		}
		// Free always shows $0, so exactly one price means Pro shows none.
		if n := strings.Count(body, `<p class="home-price">`); n != 1 {
			t.Errorf("found %d prices, want 1 (Free only) with no Pro price configured", n)
		}
	})
}

// siteHostsConfig is production's shape: the company's domain and the API's
// are two names for one app.
func siteHostsConfig() *viper.Viper {
	cfg := viper.New()
	cfg.Set("site.home_host", "securityaccelerated.com")
	cfg.Set("site.api_host", "api.securityaccelerated.com")
	return cfg
}

func getAs(cfg *viper.Viper, host, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	req.Host = host
	w := httptest.NewRecorder()
	docsRouterWithData(nil, cfg, nil).ServeHTTP(w, req)
	return w
}

// One app answers for both names, so the root has to tell them apart: the
// company page on the company's domain, the way into the docs everywhere else.
func TestHome_HostDecidesTheRoot(t *testing.T) {
	cfg := siteHostsConfig()

	for _, tc := range []struct {
		host     string
		wantHome bool
	}{
		{"securityaccelerated.com", true},
		{"www.securityaccelerated.com", true},
		{"SecurityAccelerated.com:443", true},
		{"securityaccelerated.com.", true},
		{"api.securityaccelerated.com", false},
		{"security-accelerated-intelligence-api.fly.dev", false},
		// A suffix match would hand the page to someone else's domain.
		{"notsecurityaccelerated.com", false},
		{"securityaccelerated.com.example.org", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			w := getAs(cfg, tc.host, "/")

			if tc.wantHome {
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
				}
				if !strings.Contains(w.Body.String(), "<title>Security Accelerated</title>") {
					t.Error("expected the company home page")
				}
				return
			}
			// 302 on purpose: which host gets the page is configuration, and
			// a browser holds on to a 301 after the configuration changes.
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			if loc := w.Header().Get("Location"); loc != "/docs" {
				t.Errorf("Location = %q, want /docs", loc)
			}
		})
	}

	// Unset is the default, and the one local development runs with: there is
	// only one hostname there, and the page has to be reachable on it.
	t.Run("no home host configured", func(t *testing.T) {
		if w := getAs(viper.New(), "localhost:8080", "/"); w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// With the two names configured, each site's links to the other have to name
// it. A relative link would keep the docs on the company's domain, and send
// the docs' brand link to a root that redirects straight back to the docs.
func TestHome_SitesLinkToEachOtherByName(t *testing.T) {
	cfg := siteHostsConfig()

	t.Run("home page links to the docs on the API host", func(t *testing.T) {
		body := getAs(cfg, "securityaccelerated.com", "/").Body.String()

		for _, want := range []string{
			`href="https://api.securityaccelerated.com/docs"`,
			`href="https://api.securityaccelerated.com/docs/domain"`,
			`href="https://api.securityaccelerated.com/docs/openapi.yaml"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("home page does not contain %q", want)
			}
		}
		if m := regexp.MustCompile(`<a [^>]*href="/docs[^"]*"`).FindString(body); m != "" {
			t.Errorf("home page still links to the docs on its own host: %s", m)
		}
		// The assets stay same-origin: the CSP allows nothing else.
		if !strings.Contains(body, `<link rel="stylesheet" href="/docs/styles.css">`) {
			t.Error("the stylesheet must stay a same-origin path")
		}
	})

	for _, page := range allDocsHTML() {
		t.Run("brand link on "+page.Path, func(t *testing.T) {
			configured := getAs(cfg, "api.securityaccelerated.com", page.Path).Body.String()
			if !strings.Contains(configured, `<a href="https://securityaccelerated.com/" class="topbar-brand">`) {
				t.Error("brand link does not go to the home host")
			}

			unconfigured := getAs(nil, "localhost:8080", page.Path).Body.String()
			if !strings.Contains(unconfigured, `<a href="/" class="topbar-brand">`) {
				t.Error("brand link should be the local root when no home host is set")
			}
		})
	}
}
