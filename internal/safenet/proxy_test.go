package safenet

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSafeProxy_BlocksLocalhostHTTP(t *testing.T) {
	proxy, ln, err := NewSafeProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// Start a target on localhost — the proxy should block the connection
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

	// HTTPS triggers CONNECT; private IPs should be blocked at dial time
	_, err = client.Get("https://10.0.0.1/")
	if err == nil {
		t.Fatal("expected CONNECT to private IP to fail, but request succeeded")
	}
}
