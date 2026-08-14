package safenet

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/logging"
	"go.uber.org/zap"
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

		// Bounds how long a connection may take to send its request headers.
		// Without it a client that opens a socket and dribbles headers holds a
		// goroutine indefinitely. The listener is on 127.0.0.1 and the only
		// intended client is our own headless Chrome, so this is defense in
		// depth rather than an exposed hole — but the cost is one field.
		//
		// It bounds the header read only, never the body or a CONNECT tunnel,
		// so a long-running screenshot capture is unaffected. Matched to the
		// dial timeout above rather than made configurable: nothing operational
		// tunes this, and a second knob for a loopback proxy earns nothing.
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Logger().Error("safe proxy server failed", zap.Error(err))
		}
	}()

	return srv, ln, nil
}

// handleConnect handles HTTPS CONNECT tunneling.
func handleConnect(w http.ResponseWriter, r *http.Request, dialer *net.Dialer) {
	targetConn, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		writeProxyError(w, "proxy connect failed", err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		closeConn(targetConn, "target")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		logging.Logger().Warn("proxy hijack failed", zap.Error(err))
		closeConn(targetConn, "target")
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		logging.Logger().Warn("proxy connect response write failed", zap.Error(err))
		closeConn(clientConn, "client")
		closeConn(targetConn, "target")
		return
	}

	go transfer(targetConn, clientConn)
	go transfer(clientConn, targetConn)
}

// hopByHopHeaders are HTTP headers that are meaningful only for a single
// transport-level connection and must not be forwarded by proxies.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// handleHTTP handles plain HTTP requests by forwarding them through the safe dialer.
func handleHTTP(w http.ResponseWriter, r *http.Request, dialer *net.Dialer) {
	removeHopByHop(r.Header)

	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		writeProxyError(w, "proxy round trip failed", err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logging.Logger().Debug("proxy response body close failed", zap.Error(err))
		}
	}()

	removeHopByHop(resp.Header)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil && !errors.Is(err, net.ErrClosed) {
		logging.Logger().Warn("proxy response copy failed", zap.Error(err))
	}
}

// removeHopByHop strips standard hop-by-hop headers and any additional headers
// named by the Connection header (per RFC 7230 §6.1).
func removeHopByHop(h http.Header) {
	// Parse Connection header for additional hop-by-hop header names before deleting it.
	for _, v := range h["Connection"] {
		for _, name := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				h.Del(trimmed)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer closeConn(dst, "proxy-dst")
	defer closeConn(src, "proxy-src")

	if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
		logging.Logger().Debug("proxy stream copy failed", zap.Error(err))
	}
}

func writeProxyError(w http.ResponseWriter, msg string, err error) {
	logging.Logger().Warn(msg, zap.Error(err))

	message := "upstream request failed"
	var blocked *BlockedError
	if errors.As(err, &blocked) {
		message = "upstream request blocked by network policy"
	}
	http.Error(w, message, http.StatusBadGateway)
}

func closeConn(conn io.Closer, name string) {
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		logging.Logger().Debug("proxy close failed",
			zap.String("conn", name),
			zap.Error(err),
		)
	}
}
