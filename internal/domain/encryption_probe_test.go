package domain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

// testNow is the clock every test session reports, so expiry arithmetic is
// deterministic.
var testNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// certSpec describes a certificate to build in memory. A nil parent makes it
// self-signed.
type certSpec struct {
	cn        string
	key       crypto.Signer
	notBefore time.Time
	notAfter  time.Time
	dnsNames  []string
	isCA      bool
	parent    *x509.Certificate
	parentKey crypto.Signer
	// sigAlg overrides the signature algorithm; zero picks the default for
	// the signing key.
	sigAlg x509.SignatureAlgorithm
}

func makeCert(t *testing.T, spec certSpec) (cert *x509.Certificate, der []byte) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: spec.cn},
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		DNSNames:              spec.dnsNames,
		IsCA:                  spec.isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    spec.sigAlg,
	}
	parent, signer := tmpl, spec.key
	if spec.parent != nil {
		parent, signer = spec.parent, spec.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, spec.key.Public(), signer)
	if err != nil {
		t.Fatalf("create certificate %q: %v", spec.cn, err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", spec.cn, err)
	}
	return cert, der
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// serverCertificate is a self-signed ECDSA certificate valid for 90 days,
// with 80 of them left at testNow.
func serverCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key := ecdsaKey(t)
	_, der := makeCert(t, certSpec{
		cn:        "probe.test",
		key:       key,
		notBefore: testNow.AddDate(0, 0, -10),
		notAfter:  testNow.AddDate(0, 0, 80),
		dnsNames:  []string{"probe.test", "www.probe.test"},
	})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// loopbackSession points a session at a listener on loopback, which the
// production dialer refuses by design. Its trust store is empty, so a trust
// verdict here never depends on the roots installed on the machine.
func loopbackSession(t *testing.T, ln net.Listener) *session {
	t.Helper()
	return &session{
		host:  "probe.test",
		addr:  ln.Addr().(*net.TCPAddr).AddrPort(),
		dial:  (&net.Dialer{}).DialContext,
		now:   func() time.Time { return testNow },
		roots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
	}
}

// startTLSServer runs a TLS server on loopback that completes each handshake
// and then waits for the client to hang up.
func startTLSServer(t *testing.T, cfg *tls.Config) *session {
	t.Helper()
	if len(cfg.Certificates) == 0 {
		cfg.Certificates = []tls.Certificate{serverCertificate(t)}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return loopbackSession(t, ln)
}

// startTCPServer runs a plain TCP server on loopback and hands each accepted
// connection to handle.
func startTCPServer(t *testing.T, handle func(net.Conn)) *session {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return loopbackSession(t, ln)
}

func setProbeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := EncryptionProbeTimeout
	EncryptionProbeTimeout = d
	t.Cleanup(func() { EncryptionProbeTimeout = prev })
}

func TestPickAddr(t *testing.T) {
	addr := netip.MustParseAddr
	tests := []struct {
		name    string
		addrs   []netip.Addr
		want    netip.Addr
		blocked bool
		wantErr bool
	}{
		{name: "prefers ipv4 over an earlier ipv6", addrs: []netip.Addr{addr("2606:4700::1"), addr("93.184.216.34")}, want: addr("93.184.216.34")},
		{name: "ipv6 when there is no ipv4", addrs: []netip.Addr{addr("2606:4700::1")}, want: addr("2606:4700::1")},
		{name: "skips a private address", addrs: []netip.Addr{addr("10.0.0.5"), addr("93.184.216.34")}, want: addr("93.184.216.34")},
		{name: "unmaps ipv4-mapped ipv6", addrs: []netip.Addr{addr("::ffff:93.184.216.34")}, want: addr("93.184.216.34")},
		{name: "all private is blocked", addrs: []netip.Addr{addr("127.0.0.1"), addr("192.168.1.1")}, blocked: true, wantErr: true},
		{name: "mapped private is blocked", addrs: []netip.Addr{addr("::ffff:10.0.0.1")}, blocked: true, wantErr: true},
		{name: "no addresses", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pickAddr(tt.addrs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("pickAddr() error = %v, wantErr %v", err, tt.wantErr)
			}
			var blocked *safenet.BlockedError
			if errors.As(err, &blocked) != tt.blocked {
				t.Errorf("pickAddr() error = %v, want BlockedError = %v", err, tt.blocked)
			}
			if got != tt.want {
				t.Errorf("pickAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

// newSession is the only place a hostname from a caller becomes an address to
// connect to, so its three answers are worth pinning down against a real
// resolver: a public address is pinned on 443, a private one is refused, and
// a name that does not exist is an error.
func TestNewSession(t *testing.T) {
	t.Run("pins a public address on port 443", func(t *testing.T) {
		server, _ := startDNSServer(t, testZone{A: []string{"10.0.0.7", "93.184.216.34"}})
		useLocalResolver(t, server)

		s, err := newSession(context.Background(), "probe.test")
		if err != nil {
			t.Fatalf("newSession() error = %v", err)
		}
		if want := netip.MustParseAddrPort("93.184.216.34:443"); s.addr != want {
			t.Errorf("addr = %v, want %v", s.addr, want)
		}
		if s.host != "probe.test" {
			t.Errorf("host = %q, want probe.test", s.host)
		}
	})

	t.Run("refuses a host with only private addresses", func(t *testing.T) {
		server, _ := startDNSServer(t, testZone{A: []string{"127.0.0.1"}})
		useLocalResolver(t, server)

		_, err := newSession(context.Background(), "internal.test")
		var blocked *safenet.BlockedError
		if !errors.As(err, &blocked) {
			t.Errorf("newSession() error = %v, want a BlockedError", err)
		}
	})

	t.Run("fails for a name that does not exist", func(t *testing.T) {
		server, _ := startDNSServer(t, testZone{NXDOMAIN: true})
		useLocalResolver(t, server)

		_, err := newSession(context.Background(), "nope.test")
		if err == nil {
			t.Fatal("newSession() error = nil, want a resolution error")
		}
		// A name that does not resolve is a finding about the target, so it
		// must not count toward alerting.
		if !IsExpectedError(err) {
			t.Errorf("IsExpectedError(%v) = false, want true", err)
		}
	})
}

func TestProbeProtocols(t *testing.T) {
	tests := []struct {
		name       string
		min, max   uint16
		curves     []tls.CurveID
		want       map[string]bool
		wantLegacy bool
	}{
		{
			name: "modern server",
			min:  tls.VersionTLS12, max: tls.VersionTLS13,
			want: map[string]bool{"TLS 1.3": true, "TLS 1.2": true, "TLS 1.1": false, "TLS 1.0": false},
		},
		{
			name: "tls 1.3 only",
			min:  tls.VersionTLS13, max: tls.VersionTLS13,
			want: map[string]bool{"TLS 1.3": true, "TLS 1.2": false, "TLS 1.1": false, "TLS 1.0": false},
		},
		{
			name: "legacy server without tls 1.3",
			min:  tls.VersionTLS10, max: tls.VersionTLS12,
			want:       map[string]bool{"TLS 1.3": false, "TLS 1.2": true, "TLS 1.1": true, "TLS 1.0": true},
			wantLegacy: true,
		},
		{
			// A group the standard library does not offer by default. The probe
			// asks about the version, so it has to offer every group it can
			// speak or this server reads as refusing TLS 1.3.
			name: "tls 1.3 server that only takes pure ml-kem",
			min:  tls.VersionTLS13, max: tls.VersionTLS13,
			curves: []tls.CurveID{tls.MLKEM1024},
			want:   map[string]bool{"TLS 1.3": true, "TLS 1.2": false, "TLS 1.1": false, "TLS 1.0": false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := startTLSServer(t, &tls.Config{MinVersion: tt.min, MaxVersion: tt.max, CurvePreferences: tt.curves})

			info, err := probeProtocols(context.Background(), s)
			if err != nil {
				t.Fatalf("probeProtocols() error = %v", err)
			}
			if len(info.Versions) != len(tt.want) {
				t.Fatalf("got %d versions, want %d", len(info.Versions), len(tt.want))
			}
			for _, v := range info.Versions {
				if v.Accepted != tt.want[v.Name] {
					t.Errorf("%s accepted = %v, want %v", v.Name, v.Accepted, tt.want[v.Name])
				}
			}
			if info.LegacyAccepted != tt.wantLegacy {
				t.Errorf("LegacyAccepted = %v, want %v", info.LegacyAccepted, tt.wantLegacy)
			}
			if info.IP != "127.0.0.1" || !info.ProbedAt.Equal(testNow) {
				t.Errorf("evidence = %s at %s, want 127.0.0.1 at %s", info.IP, info.ProbedAt, testNow)
			}
		})
	}
}

// The three ways a probe can fail to get a TLS answer must stay distinct:
// only a server that answered and refused may be reported as ErrNoHandshake,
// and none of them may come back as a result. Each is a finding about the
// target, so none of them may count toward alerting either.
func TestProbeFailureModes(t *testing.T) {
	t.Run("server hangs up on every handshake", func(t *testing.T) {
		s := startTCPServer(t, func(c net.Conn) { _ = c.Close() })

		if _, err := probeProtocols(context.Background(), s); !errors.Is(err, ErrNoHandshake) {
			t.Errorf("probeProtocols() error = %v, want ErrNoHandshake", err)
		}
		if _, err := probeKeyExchange(context.Background(), s); !errors.Is(err, ErrNoHandshake) {
			t.Errorf("probeKeyExchange() error = %v, want ErrNoHandshake", err)
		}
		if _, err := probeCertificate(context.Background(), s); !errors.Is(err, ErrNoHandshake) {
			t.Errorf("probeCertificate() error = %v, want ErrNoHandshake", err)
		}
	})

	t.Run("server accepts the connection and says nothing", func(t *testing.T) {
		setProbeTimeout(t, 150*time.Millisecond)
		s := startTCPServer(t, func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		})

		_, err := probeProtocols(context.Background(), s)
		if err == nil || errors.Is(err, ErrNoHandshake) {
			t.Errorf("probeProtocols() error = %v, want a timeout that is not ErrNoHandshake", err)
		}
		if !IsExpectedError(err) {
			t.Errorf("IsExpectedError(%v) = false, want true", err)
		}
	})

	t.Run("nothing is listening", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		s := loopbackSession(t, ln)
		_ = ln.Close()

		_, err = probeProtocols(context.Background(), s)
		if err == nil || errors.Is(err, ErrNoHandshake) {
			t.Errorf("probeProtocols() error = %v, want a connect error that is not ErrNoHandshake", err)
		}
		if !IsExpectedError(err) {
			t.Errorf("IsExpectedError(%v) = false, want true", err)
		}
	})
}

func TestProbeKeyExchange(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *tls.Config
		wantAccepted   []string
		wantVerdict    string
		wantNegotiated string
	}{
		{
			name:           "hybrid post-quantum and classical",
			cfg:            &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}},
			wantAccepted:   []string{"X25519MLKEM768", "x25519"},
			wantVerdict:    KeyExchangePostQuantum,
			wantNegotiated: "X25519MLKEM768",
		},
		{
			name:           "pure ml-kem only",
			cfg:            &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.MLKEM1024}},
			wantAccepted:   []string{"MLKEM1024"},
			wantVerdict:    KeyExchangePostQuantum,
			wantNegotiated: "MLKEM1024",
		},
		{
			name:           "classical only",
			cfg:            &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.CurveP384}},
			wantAccepted:   []string{"secp384r1"},
			wantVerdict:    KeyExchangeClassical,
			wantNegotiated: "secp384r1",
		},
		{
			// Hybrids are TLS 1.3 only, so a TLS 1.2 server must come back
			// classical even though it lists one.
			name:           "tls 1.2 server",
			cfg:            &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256}},
			wantAccepted:   []string{"secp256r1"},
			wantVerdict:    KeyExchangeClassical,
			wantNegotiated: "secp256r1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := startTLSServer(t, tt.cfg)

			info, err := probeKeyExchange(context.Background(), s)
			if err != nil {
				t.Fatalf("probeKeyExchange() error = %v", err)
			}
			if len(info.Groups) != len(probedGroups) {
				t.Fatalf("got %d groups, want one per probed group (%d)", len(info.Groups), len(probedGroups))
			}

			want := make(map[string]bool, len(tt.wantAccepted))
			for _, name := range tt.wantAccepted {
				want[name] = true
			}
			for _, g := range info.Groups {
				if g.Accepted != want[g.Name] {
					t.Errorf("%s accepted = %v, want %v", g.Name, g.Accepted, want[g.Name])
				}
			}
			if info.Verdict != tt.wantVerdict {
				t.Errorf("Verdict = %q, want %q", info.Verdict, tt.wantVerdict)
			}
			if info.Negotiated != tt.wantNegotiated {
				t.Errorf("Negotiated = %q, want %q", info.Negotiated, tt.wantNegotiated)
			}
		})
	}
}

func TestProbeCertificate(t *testing.T) {
	s := startTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS12})

	info, err := probeCertificate(context.Background(), s)
	if err != nil {
		t.Fatalf("probeCertificate() error = %v", err)
	}
	if len(info.Chain) != 1 {
		t.Fatalf("got %d certificates, want 1", len(info.Chain))
	}
	leaf := info.Chain[0]
	if leaf.Subject != "probe.test" || leaf.KeyAlgorithm != "ECDSA" || leaf.KeyBits != 256 || !leaf.SelfSigned {
		t.Errorf("leaf = %+v, want a self-signed 256-bit ECDSA certificate for probe.test", leaf)
	}
	if info.DaysUntilExpiry != 80 || info.ValidityDays != 90 {
		t.Errorf("DaysUntilExpiry = %d, ValidityDays = %d, want 80 and 90", info.DaysUntilExpiry, info.ValidityDays)
	}
	if info.ExpiryVerdict != ExpiryValid || info.AlgorithmVerdict != AlgorithmsClassical {
		t.Errorf("verdicts = %q / %q, want valid / classical", info.ExpiryVerdict, info.AlgorithmVerdict)
	}
	if len(info.SANs) != 2 {
		t.Errorf("SANs = %v, want two names", info.SANs)
	}
	// A self-signed certificate nobody trusts is the answer, not an error: the
	// lookup succeeded and says so in its verdicts.
	if info.TrustVerdict != TrustUntrusted || info.HostnameVerdict != HostnameMatch {
		t.Errorf("verdicts = %q / %q, want untrusted / match", info.TrustVerdict, info.HostnameVerdict)
	}
}

// A missing trust store is our fault, not a fact about the host. The lookup
// must fail, so nothing is cached, and the failure must alert.
func TestProbeCertificate_NoTrustStoreFailsTheLookup(t *testing.T) {
	s := startTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS12})
	s.roots = func() (*x509.CertPool, error) { return checkTrustStore(x509.NewCertPool(), nil) }

	info, err := probeCertificate(context.Background(), s)
	if info != nil {
		t.Errorf("probeCertificate() returned a result (trust_verdict %q) with no trust store to judge against", info.TrustVerdict)
	}
	if !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Fatalf("probeCertificate() error = %v, want ErrTrustStoreUnavailable", err)
	}
	if IsExpectedError(err) {
		t.Error("a missing trust store was classified as expected; it would never alert")
	}
}

func TestCheckTrustStore(t *testing.T) {
	loaded := x509.NewCertPool()
	cert, _ := makeCert(t, certSpec{cn: "Some Root", key: ecdsaKey(t), isCA: true, notBefore: testNow.AddDate(0, 0, -1), notAfter: testNow.AddDate(1, 0, 0)})
	loaded.AddCert(cert)

	if pool, err := checkTrustStore(loaded, nil); err != nil || pool != loaded {
		t.Errorf("checkTrustStore(loaded) = %v, %v; want the pool and no error", pool, err)
	}
	// What Linux hands back when the image has no CA bundle: no error, no
	// certificates.
	if _, err := checkTrustStore(x509.NewCertPool(), nil); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Errorf("checkTrustStore(empty) error = %v, want ErrTrustStoreUnavailable", err)
	}
	if _, err := checkTrustStore(nil, errors.New("permission denied")); !errors.Is(err, ErrTrustStoreUnavailable) {
		t.Errorf("checkTrustStore(load error) error = %v, want ErrTrustStoreUnavailable", err)
	}
	// The machine running the suite has roots, and so must production.
	if _, err := systemTrustStore(); err != nil {
		t.Errorf("systemTrustStore() error = %v on this machine", err)
	}
}

// The certificate probe has to reach a server whatever key exchange it insists
// on, including a group the standard library leaves out of its defaults.
func TestProbeCertificate_ServerWithNonDefaultGroup(t *testing.T) {
	s := startTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.MLKEM1024}})

	info, err := probeCertificate(context.Background(), s)
	if err != nil {
		t.Fatalf("probeCertificate() error = %v, want the certificate of a pure ML-KEM server", err)
	}
	if len(info.Chain) != 1 {
		t.Errorf("got %d certificates, want 1", len(info.Chain))
	}
}

// The session's host is what the hostname verdict is judged against, so a
// certificate for another name must come back as a mismatch, not an error.
func TestProbeCertificate_HostnameMismatch(t *testing.T) {
	s := startTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS12})
	s.host = "other.test"

	info, err := probeCertificate(context.Background(), s)
	if err != nil {
		t.Fatalf("probeCertificate() error = %v", err)
	}
	if info.HostnameVerdict != HostnameMismatch {
		t.Errorf("HostnameVerdict = %q, want %q", info.HostnameVerdict, HostnameMismatch)
	}
}
