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
