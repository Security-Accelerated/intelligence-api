package safenet

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// --- Success-path tests (plain dialer, proves forwarding logic) ---

func TestProxy_ForwardsHTTPSuccessfully(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "proxied")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from target"))
	}))
	defer target.Close()

	// Use a plain dialer so we can reach the localhost test server
	proxy, ln, err := newProxy(&net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Test"); got != "proxied" {
		t.Errorf("X-Test header = %q, want %q", got, "proxied")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from target" {
		t.Errorf("body = %q, want %q", body, "hello from target")
	}
}

func TestProxy_ForwardsCONNECTSuccessfully(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello via TLS"))
	}))
	defer target.Close()

	// Use a plain dialer so we can reach the localhost TLS test server
	proxy, ln, err := newProxy(&net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("CONNECT tunnel through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello via TLS" {
		t.Errorf("body = %q, want %q", body, "hello via TLS")
	}
}

// --- Block tests (SafeDialer, proves SSRF protection) ---

func TestSafeProxy_BlocksLocalhostHTTP(t *testing.T) {
	proxy, ln, err := NewSafeProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for localhost target, got %d", resp.StatusCode)
	}
}

func TestSafeProxy_BlocksPrivateIPs(t *testing.T) {
	proxy, ln, err := NewSafeProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	privateTargets := []string{
		"http://10.0.0.1/",
		"http://192.168.1.1/",
		"http://172.16.0.1/",
		"http://169.254.169.254/latest/meta-data/",
	}

	for _, target := range privateTargets {
		t.Run(target, func(t *testing.T) {
			resp, err := client.Get(target)
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("expected 502 for %s, got %d", target, resp.StatusCode)
			}
		})
	}
}

func TestSafeProxy_BlocksCONNECTToPrivate(t *testing.T) {
	proxy, ln, err := NewSafeProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	_, err = client.Get("https://10.0.0.1/")
	if err == nil {
		t.Fatal("expected CONNECT to private IP to fail, but request succeeded")
	}
}
