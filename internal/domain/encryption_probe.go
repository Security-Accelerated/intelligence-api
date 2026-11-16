package domain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// The TLS probe behind the encryption lookups (protocols, key_exchange,
// certificate). Each rule in this file is a way to return a wrong answer that
// would then be cached for hours; docs/decisions.md has the reasoning.

// probePort is the only port an encryption lookup connects to. Taking a port
// from the caller would turn the endpoint into a general port prober, so that
// stays out until there is a decision to offer it.
const probePort = 443

// EncryptionProbeTimeout bounds a single handshake, TCP connect included. Set
// from encryption.probe_timeout at startup.
var EncryptionProbeTimeout = 5 * time.Second

// ErrNoHandshake means every handshake a lookup tried was refused. That cannot
// be told apart from a host that is blocking us, so it is reported as a failed
// lookup rather than as "this host accepts nothing".
var ErrNoHandshake = errors.New("no TLS handshake succeeded on port 443")

// session is one lookup's view of a host. A lookup makes several handshakes,
// and all of them go to the one address picked here: a host with several
// addresses can be configured differently on each, and mixing them would
// produce a result that is true of no single server.
type session struct {
	host string
	addr netip.AddrPort
	// dial opens the TCP connection. Production uses safenet, which refuses
	// private and reserved addresses; tests substitute a plain dialer to reach
	// a loopback server.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	now  func() time.Time
	// roots is the trust store the certificate lookup judges a chain against.
	// Nil means the system roots; tests supply their own so the result does
	// not depend on the machine running them.
	roots *x509.CertPool
}

// newSession resolves host through the lookup resolver and pins one public
// address for the handshakes that follow.
func newSession(ctx context.Context, host string) (*session, error) {
	addrs, err := Resolver().LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	addr, err := pickAddr(addrs)
	if err != nil {
		return nil, err
	}
	return &session{
		host: host,
		addr: netip.AddrPortFrom(addr, probePort),
		dial: safenet.SafeDialer(EncryptionProbeTimeout).DialContext,
		now:  time.Now,
	}, nil
}

// pickAddr chooses the address to probe: the first public IPv4 address, or
// failing that the first public IPv6 one. IPv4 first because not every
// environment this runs in has an IPv6 route, and a connect failure of our own
// making would be reported as the target's.
//
// A host whose addresses are all private or reserved yields a
// safenet.BlockedError, the same error the dialer would raise. The dialer
// still checks again at connect time; this only produces the clearer message
// earlier.
func pickAddr(addrs []netip.Addr) (netip.Addr, error) {
	var firstV6 netip.Addr
	var blocked netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if safenet.IsPrivateAddr(a) {
			if !blocked.IsValid() {
				blocked = a
			}
			continue
		}
		if a.Is4() {
			return a, nil
		}
		if !firstV6.IsValid() {
			firstV6 = a
		}
	}
	if firstV6.IsValid() {
		return firstV6, nil
	}
	if blocked.IsValid() {
		return netip.Addr{}, &safenet.BlockedError{IP: blocked}
	}
	return netip.Addr{}, errors.New("host has no addresses")
}

// evidence records where and when this session observed the host.
func (s *session) evidence() Evidence {
	return Evidence{IP: s.addr.Addr().String(), ProbedAt: s.now().UTC()}
}

// rejectedError marks a handshake the server answered and refused: an alert, a
// reset, a closed connection, or parameters this client would not accept. It
// is an answer about the offer, not a failure of the lookup.
type rejectedError struct{ cause error }

func (e *rejectedError) Error() string { return "handshake rejected: " + e.cause.Error() }
func (e *rejectedError) Unwrap() error { return e.cause }

// handshake makes one TLS handshake with cfg and returns the negotiated state.
// It sets ServerName and InsecureSkipVerify on cfg, so pass a fresh one.
//
// There are three outcomes, and keeping them apart is what makes a result
// trustworthy:
//
//   - success: the server accepted what cfg offered.
//   - *rejectedError: the TCP connection opened and the handshake then failed.
//     The server does not accept this offer.
//   - any other error: the connection never opened, or the handshake timed
//     out. Nothing was learned, so the caller must fail the lookup rather than
//     record a refusal. A failed lookup is retried; a wrong "not accepted"
//     would be cached.
//
// A timeout counts as "nothing learned" even though some middleboxes silently
// drop offers they dislike. Treating silence as refusal would let one lost
// packet be cached as a finding.
func (s *session) handshake(ctx context.Context, cfg *tls.Config) (*tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, EncryptionProbeTimeout)
	defer cancel()

	conn, err := s.dial(ctx, "tcp", s.addr.String())
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	cfg.ServerName = s.host
	// InsecureSkipVerify is intentional, as in LookupSSL: the point is to
	// report what the server presents, including expired, self-signed and
	// mismatched certificates. Verifying during the handshake would turn the
	// answer the caller asked for into a handshake error. The certificate
	// lookup judges the chain afterwards and reports the outcome as data. This
	// connection carries no credentials and reads no data; it exists only to
	// see what the target negotiates.
	cfg.InsecureSkipVerify = true

	client := tls.Client(conn, cfg)
	if err := client.HandshakeContext(ctx); err != nil {
		if timedOut(ctx, err) {
			return nil, fmt.Errorf("handshake: %w", err)
		}
		return nil, &rejectedError{cause: err}
	}
	state := client.ConnectionState()
	return &state, nil
}

// offer makes one handshake and reports whether the server accepted it. A
// non-nil error means the question could not be answered.
func (s *session) offer(ctx context.Context, cfg *tls.Config) (*tls.ConnectionState, bool, error) {
	state, err := s.handshake(ctx, cfg)
	var rejected *rejectedError
	switch {
	case err == nil:
		return state, true, nil
	case errors.As(err, &rejected):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// timedOut reports whether a handshake failed because time ran out rather
// than because the server answered.
func timedOut(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// everyCipherSuite lists every TLS 1.0–1.2 cipher suite the standard library
// implements, including the ones it marks insecure. Probes that ask "does the
// server speak this at all" offer the lot: a server that only has RSA key
// exchange or CBC suites left still accepts TLS, and leaving those out would
// report it as refusing.
func everyCipherSuite() []uint16 {
	secure, insecure := tls.CipherSuites(), tls.InsecureCipherSuites()
	ids := make([]uint16, 0, len(secure)+len(insecure))
	for _, suite := range secure {
		ids = append(ids, suite.ID)
	}
	for _, suite := range insecure {
		ids = append(ids, suite.ID)
	}
	return ids
}

// everyGroup lists every key exchange group the probe can speak, post-quantum
// first. The standard library's default offer leaves some of them out (pure
// ML-KEM, for one), so a probe that leaves CurvePreferences empty cannot
// complete a handshake with a server that insists on one of those, and would
// report it as refusing TLS altogether.
func everyGroup() []tls.CurveID {
	ids := make([]tls.CurveID, 0, len(probedGroups))
	for _, g := range probedGroups {
		ids = append(ids, g.id)
	}
	return ids
}
