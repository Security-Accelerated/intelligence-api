package safenet

import (
	"io"
	"net"
	"net/http"
	"time"
)

// NewSafeProxy returns an HTTP proxy server that routes all outbound connections
// through SafeDialer, blocking requests to private/reserved IP ranges. This is
// designed for use with headless Chrome's --proxy-server flag so that browser
// traffic inherits SSRF protection.
//
// The returned server's Addr field contains the listener address (including the
// assigned port when using ":0"). Call Close() to shut down.
func NewSafeProxy() (*http.Server, net.Listener, error) {
	return newProxy(SafeDialer(10 * time.Second))
}

// newProxy creates a proxy server with the given dialer. Extracted for testability:
// tests can pass a plain net.Dialer to verify forwarding logic against localhost
// targets, while NewSafeProxy wires in SafeDialer for SSRF protection.
func newProxy(dialer *net.Dialer) (*http.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r, dialer)
			} else {
				handleHTTP(w, r, dialer)
			}
		}),
	}

	go srv.Serve(ln)

	return srv, ln, nil
}

// handleConnect handles HTTPS CONNECT tunneling.
func handleConnect(w http.ResponseWriter, r *http.Request, dialer *net.Dialer) {
	targetConn, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		clientConn.Close()
		targetConn.Close()
		return
	}

	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)
}

// handleHTTP handles plain HTTP requests by forwarding them through the safe dialer.
func handleHTTP(w http.ResponseWriter, r *http.Request, dialer *net.Dialer) {
	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
