package domain

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultDNSServers is the ordered list of external DNS resolvers used for
// all runtime lookups (domain intelligence, IP intelligence, etc.).
var DefaultDNSServers = []string{
	"8.8.8.8:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"208.67.222.222:53", // OpenDNS
}

// DefaultDNSDialTimeout is the per-server connection timeout.
var DefaultDNSDialTimeout = 30 * time.Second

// DefaultDNSPerServerTimeout bounds how long one server gets to answer before
// the query is retried against the next one. A healthy public resolver answers
// in well under 50ms, so this is generous while keeping the cost of failing
// over to a blackholed server small.
var DefaultDNSPerServerTimeout = 2 * time.Second

// NewExternalResolver creates a net.Resolver that queries the given servers in
// order, moving to the next one when a server fails to answer.
//
// Failover happens in two places, because neither alone is sufficient.
//
// Dialing catches the servers that are unreachable outright — no route, bad
// address — and dialNext walks past those. But it cannot catch the common case:
// UDP is connectionless, so net.Dialer.DialContext succeeds for any routable
// address, sending no packet and verifying nothing. A dial-only loop therefore
// settles on the first server and never reaches the rest, however dead that
// server is. The real failover has to happen around the query itself, which is
// what failoverConn.Read does: it retries the pending query against the next
// server when the current one goes quiet.
func NewExternalResolver(servers []string, dialTimeout time.Duration) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	if dialTimeout <= 0 {
		dialTimeout = DefaultDNSDialTimeout
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The address the resolver asks for comes from resolv.conf and is
			// deliberately ignored: these lookups must use the configured
			// external servers, not whatever the host is pointed at.
			c := &failoverConn{
				servers: servers,
				network: network,
				dialer:  &net.Dialer{Timeout: dialTimeout},
				perTry:  DefaultDNSPerServerTimeout,
			}
			if err := c.dialNext(ctx); err != nil {
				return nil, err
			}

			// Go's resolver picks its wire framing by type-asserting the conn:
			// a net.PacketConn gets datagram framing, anything else gets TCP
			// stream framing with a two-byte length prefix. A plain net.Conn
			// wrapper around a UDP socket therefore silently downgrades every
			// query to stream framing on a datagram socket, which no DNS server
			// answers. Preserve the distinction.
			if _, ok := c.conn.(net.PacketConn); ok {
				return &failoverPacketConn{c}, nil
			}
			return c, nil
		},
	}
}

// failoverPacketConn is failoverConn for datagram networks. It exists purely so
// the value returned from Dial satisfies net.PacketConn, which is how Go's
// resolver decides to use datagram rather than TCP framing. The methods are
// thin: the socket is connected, so the peer address is fixed.
type failoverPacketConn struct{ *failoverConn }

func (c *failoverPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c *failoverPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.Write(b)
}

// failoverConn wraps a connection to one DNS server and transparently retries
// the pending query against the next server when the current one does not
// answer in time.
//
// It exists because Go's resolver treats the conn returned by Dial as a single
// server: it writes one query, reads one reply, and only tries another server
// if the conn errors. Over UDP a blackholed server produces neither — the write
// succeeds and the read simply never completes — so without this the lookup
// stalls on the first server until the caller's deadline expires.
type failoverConn struct {
	servers []string
	network string
	dialer  *net.Dialer
	perTry  time.Duration

	mu       sync.Mutex
	idx      int
	conn     net.Conn
	query    []byte    // last query written, replayed on failover
	deadline time.Time // caller-set read deadline, if any
	ctx      context.Context
}

// dialNext connects to the first server at or after c.idx that accepts a
// connection, leaving c.idx pointing at whichever one that was.
//
// Dial errors have to cascade just as read failures do. Dialing a connected UDP
// socket sends nothing, but it does perform a route lookup — so a server with
// no route to it (an IPv6 resolver on a host with no IPv6 connectivity, say)
// fails here with ENETUNREACH. Returning that error would strand the lookup on
// an unusable server while working ones sit further down the list.
func (c *failoverConn) dialNext(ctx context.Context) error {
	var lastErr error
	for ; c.idx < len(c.servers); c.idx++ {
		conn, err := c.dialer.DialContext(ctx, c.network, c.servers[c.idx])
		if err == nil {
			c.ctx = ctx
			c.conn = conn
			return nil
		}
		lastErr = err
		// The caller gave up or ran out of time: the rest would fail the same.
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers available")
	}
	return lastErr
}

// Write records the query so it can be replayed against the next server, then
// forwards it to the current one.
func (c *failoverConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.query = append(c.query[:0], b...)
	return c.conn.Write(b)
}

// Read returns the current server's reply, failing over to the next server if
// this one stays silent. Only silence and connection errors trigger failover —
// a well-formed reply is returned as-is, including one that says NXDOMAIN,
// since that is an answer rather than a failure.
func (c *failoverConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		c.conn.SetReadDeadline(c.attemptDeadline())
		n, err := c.conn.Read(b)
		if err == nil {
			return n, nil
		}

		if !c.canFailOver(err) {
			return n, err
		}

		// This server is not answering: move to the next and replay the query.
		_ = c.conn.Close()
		c.idx++
		if dialErr := c.dialNext(c.ctx); dialErr != nil {
			return 0, dialErr
		}
		if len(c.query) > 0 {
			if _, wErr := c.conn.Write(c.query); wErr != nil {
				return 0, wErr
			}
		}
	}
}

// attemptDeadline bounds one server's chance to answer: the per-server timeout,
// or the caller's deadline if that is sooner. Without the per-server bound a
// single blackholed server would consume the entire caller deadline and no
// failover would ever happen — which is precisely the bug this type fixes.
func (c *failoverConn) attemptDeadline() time.Time {
	d := time.Now().Add(c.perTry)
	if !c.deadline.IsZero() && c.deadline.Before(d) {
		return c.deadline
	}
	if dl, ok := c.ctx.Deadline(); ok && dl.Before(d) {
		return dl
	}
	return d
}

// canFailOver reports whether the pending query is worth retrying against
// another server.
//
// Any read error qualifies — a silent server times out, a refusing one gives
// ECONNREFUSED, and both mean this server produced no answer. What matters is
// only whether another server is left and whether the caller still wants the
// result.
func (c *failoverConn) canFailOver(err error) bool {
	if err == nil || c.idx >= len(c.servers)-1 {
		return false
	}
	// The caller gave up, or ran out of time: retrying helps nobody.
	if c.ctx.Err() != nil {
		return false
	}
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		return false
	}
	if dl, ok := c.ctx.Deadline(); ok && !time.Now().Before(dl) {
		return false
	}
	// We closed the conn ourselves; that is not the server's fault to retry.
	return !errors.Is(err, net.ErrClosed)
}

func (c *failoverConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

func (c *failoverConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *failoverConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline records the caller's deadline and applies it to the current
// connection. The recorded value bounds failover overall, while each individual
// attempt is additionally capped by perTry.
func (c *failoverConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return c.conn.SetDeadline(t)
}

func (c *failoverConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil // applied per attempt in Read
}

func (c *failoverConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.SetWriteDeadline(t)
}

// activeDNSServers holds the resolver addresses configured via InitResolver,
// for lookups that need raw DNS access (e.g. DNSSEC/CAA via miekg/dns) rather
// than net.Resolver.
var activeDNSServers = DefaultDNSServers

// ActiveDNSServers returns the resolver addresses configured via InitResolver
// (the defaults when InitResolver hasn't been called).
func ActiveDNSServers() []string {
	return activeDNSServers
}

// externalResolver is the resolver every intelligence lookup uses. It holds nil
// until InitResolver runs, which means the system resolver.
//
// Deliberately NOT net.DefaultResolver. Overriding the global sends every
// resolution in the process to public DNS, including the ones this service
// makes to reach its own infrastructure. Postgres and Redis addressed by a name
// only the platform's resolver knows — a Docker Compose service, a Kubernetes
// service, a Fly .internal address — then fail to resolve. It survived review
// once because app.go called InitResolver after both had connected, but
// database/sql recycles pooled connections on conn_max_lifetime, and every
// replacement opened after the override failed with "no such host".
//
// An atomic pointer rather than a plain var because tests swap it while the
// package is otherwise in use.
var externalResolver atomic.Pointer[net.Resolver]

// Resolver returns the resolver intelligence lookups should use: the external
// servers configured by InitResolver, or the system resolver before that.
//
// Use this instead of net.DefaultResolver anywhere the target is a name from
// user input. Infrastructure connections must keep using the system resolver.
func Resolver() *net.Resolver {
	if r := externalResolver.Load(); r != nil {
		return r
	}
	return net.DefaultResolver
}

// InitResolver points intelligence lookups at the given external DNS servers.
//
// Unlike the previous implementation this touches no global state beyond the
// domain package, so it is safe to call at any point during startup: nothing
// else in the process changes how it resolves names.
func InitResolver(servers []string, dialTimeout time.Duration) {
	if len(servers) == 0 {
		servers = DefaultDNSServers
	}
	activeDNSServers = servers
	externalResolver.Store(NewExternalResolver(servers, dialTimeout))
}

// SetResolverForTest swaps the lookup resolver and restores it via t.Cleanup.
// Exported for tests in other packages; the domain package's own tests use the
// local-server helper in testdns_test.go.
func SetResolverForTest(t interface{ Cleanup(func()) }, r *net.Resolver) {
	prev := externalResolver.Load()
	externalResolver.Store(r)
	t.Cleanup(func() { externalResolver.Store(prev) })
}
