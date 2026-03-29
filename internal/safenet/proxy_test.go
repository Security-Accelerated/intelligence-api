package safenet

import (
	"crypto/tls"
	"fmt"
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

func TestProxy_StripsHopByHopHeaders(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify proxy headers were stripped before reaching origin
		if got := r.Header.Get("Proxy-Connection"); got != "" {
			t.Errorf("origin received Proxy-Connection = %q, want empty", got)
		}
		if got := r.Header.Get("Proxy-Authorization"); got != "" {
			t.Errorf("origin received Proxy-Authorization = %q, want empty", got)
		}
		// Non-hop-by-hop headers should pass through
		if got := r.Header.Get("X-Custom"); got != "keep-me" {
			t.Errorf("origin X-Custom = %q, want %q", got, "keep-me")
		}
		w.Header().Set("Proxy-Connection", "should-be-stripped")
		w.Header().Set("X-Origin", "preserved")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	proxy, ln, err := newProxy(&net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}

	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Basic secret")
	req.Header.Set("X-Custom", "keep-me")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify hop-by-hop headers are stripped from response
	if got := resp.Header.Get("Proxy-Connection"); got != "" {
		t.Errorf("client received Proxy-Connection = %q, want empty", got)
	}
	// Non-hop-by-hop response headers should pass through
	if got := resp.Header.Get("X-Origin"); got != "preserved" {
		t.Errorf("client X-Origin = %q, want %q", got, "preserved")
	}
}

// --- Edge case tests ---

func TestProxy_CONNECTWriteFailure_CleansUp(t *testing.T) {
	// Start a TLS target that we can successfully dial
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	proxy, ln, err := newProxy(&net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// Manually send a CONNECT request and close the client connection immediately
	// before the proxy can write the 200 response, exercising the write-failure cleanup.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	targetAddr := target.Listener.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)

	// Close immediately to trigger write failure on the proxy side
	conn.Close()

	// Give the proxy a moment to process and clean up
	time.Sleep(50 * time.Millisecond)

	// No panic, no goroutine leak = success.
	// Verify the proxy still works by making a normal request.
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("proxy unusable after write failure: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
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
