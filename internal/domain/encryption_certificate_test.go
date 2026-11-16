package domain

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate %d-bit rsa key: %v", bits, err)
	}
	return key
}

func TestDescribeChain_AlgorithmVerdict(t *testing.T) {
	valid := func(spec certSpec) certSpec {
		spec.notBefore, spec.notAfter = testNow.AddDate(0, 0, -1), testNow.AddDate(0, 0, 30)
		return spec
	}
	ev := Evidence{IP: "93.184.216.34", ProbedAt: testNow}

	caKey := ecdsaKey(t)
	ca, _ := makeCert(t, valid(certSpec{cn: "Test CA", key: caKey, isCA: true}))

	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("generate ml-dsa key: %v", err)
	}
	pqCA, _ := makeCert(t, valid(certSpec{cn: "PQ CA", key: pqKey, isCA: true}))
	pqLeafKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("generate ml-dsa key: %v", err)
	}

	issued := func(cn string, spec certSpec) *x509.Certificate {
		spec.cn, spec.parent, spec.parentKey = cn, ca, caKey
		cert, _ := makeCert(t, valid(spec))
		return cert
	}

	classicalLeaf := issued("classical.test", certSpec{key: ecdsaKey(t)})
	weakLeaf := issued("weak.test", certSpec{key: rsaKey(t, 1024)})
	pqLeaf, _ := makeCert(t, valid(certSpec{cn: "pq.test", key: pqLeafKey, parent: pqCA, parentKey: pqKey}))
	// A post-quantum key certified by a classical CA: the signature is the
	// weak link, so the chain is classical.
	mixedLeaf := issued("mixed.test", certSpec{key: pqLeafKey})

	tests := []struct {
		name  string
		chain []*x509.Certificate
		want  string
	}{
		{"classical leaf and ca", []*x509.Certificate{classicalLeaf, ca}, AlgorithmsClassical},
		{"1024-bit rsa leaf", []*x509.Certificate{weakLeaf, ca}, AlgorithmsWeak},
		{"post-quantum leaf and ca", []*x509.Certificate{pqLeaf, pqCA}, AlgorithmsPostQuantum},
		{"post-quantum key, classical signature", []*x509.Certificate{mixedLeaf, ca}, AlgorithmsClassical},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := describeChain(tt.chain, "host.test", x509.NewCertPool(), ev)
			if info.AlgorithmVerdict != tt.want {
				t.Errorf("AlgorithmVerdict = %q, want %q (chain %+v)", info.AlgorithmVerdict, tt.want, info.Chain)
			}
			if len(info.Chain) != len(tt.chain) {
				t.Errorf("got %d chain entries, want %d", len(info.Chain), len(tt.chain))
			}
		})
	}
}

func TestSignatureStrength(t *testing.T) {
	tests := []struct {
		alg  x509.SignatureAlgorithm
		want algorithmStrength
	}{
		{x509.SHA1WithRSA, strengthWeak},
		{x509.MD5WithRSA, strengthWeak},
		{x509.ECDSAWithSHA1, strengthWeak},
		{x509.SHA256WithRSA, strengthClassical},
		{x509.ECDSAWithSHA384, strengthClassical},
		{x509.PureEd25519, strengthClassical},
		{x509.MLDSA65, strengthPostQuantum},
		{x509.UnknownSignatureAlgorithm, strengthUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			if got := signatureStrength(tt.alg); got != tt.want {
				t.Errorf("signatureStrength(%s) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestDescribeChain_Expiry(t *testing.T) {
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantDays  int
		wantValid int
		want      string
	}{
		{"valid", testNow.AddDate(0, 0, -17), testNow.AddDate(0, 0, 30), 30, 47, ExpiryValid},
		{"expires within the day", testNow.AddDate(0, 0, -89), testNow.Add(6 * time.Hour), 0, 89, ExpiryValid},
		{"expired", testNow.AddDate(0, 0, -100), testNow.Add(-36 * time.Hour), -2, 99, ExpiryExpired},
		{"not yet valid", testNow.AddDate(0, 0, 2), testNow.AddDate(0, 0, 92), 92, 90, ExpiryNotYetValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _ := makeCert(t, certSpec{cn: "expiry.test", key: ecdsaKey(t), notBefore: tt.notBefore, notAfter: tt.notAfter})

			info := describeChain([]*x509.Certificate{cert}, "expiry.test", x509.NewCertPool(), Evidence{ProbedAt: testNow})
			if info.ExpiryVerdict != tt.want {
				t.Errorf("ExpiryVerdict = %q, want %q", info.ExpiryVerdict, tt.want)
			}
			if info.DaysUntilExpiry != tt.wantDays {
				t.Errorf("DaysUntilExpiry = %d, want %d", info.DaysUntilExpiry, tt.wantDays)
			}
			if info.ValidityDays != tt.wantValid {
				t.Errorf("ValidityDays = %d, want %d", info.ValidityDays, tt.wantValid)
			}
		})
	}
}

// The trust verdict answers one question: does the chain the server sent lead
// to a root in the trust store. The cases that matter are the ones where it
// could be confused with another verdict or with a browser's leniency.
func TestDescribeChain_TrustVerdict(t *testing.T) {
	yearEitherSide := func(spec certSpec) certSpec {
		spec.notBefore, spec.notAfter = testNow.AddDate(-1, 0, 0), testNow.AddDate(1, 0, 0)
		return spec
	}

	rootKey := ecdsaKey(t)
	root, _ := makeCert(t, yearEitherSide(certSpec{cn: "Test Root", key: rootKey, isCA: true}))
	interKey := ecdsaKey(t)
	inter, _ := makeCert(t, yearEitherSide(certSpec{cn: "Test Intermediate", key: interKey, isCA: true, parent: root, parentKey: rootKey}))

	leaf := func(notBefore, notAfter time.Time) *x509.Certificate {
		cert, _ := makeCert(t, certSpec{
			cn: "trust.test", key: ecdsaKey(t), dnsNames: []string{"trust.test"},
			notBefore: notBefore, notAfter: notAfter,
			parent: inter, parentKey: interKey,
		})
		return cert
	}
	current := leaf(testNow.AddDate(0, 0, -10), testNow.AddDate(0, 0, 80))
	expired := leaf(testNow.AddDate(0, 0, -100), testNow.AddDate(0, 0, -10))
	notYetValid := leaf(testNow.AddDate(0, 0, 5), testNow.AddDate(0, 0, 95))
	selfSigned, _ := makeCert(t, certSpec{
		cn: "trust.test", key: ecdsaKey(t), dnsNames: []string{"trust.test"},
		notBefore: testNow.AddDate(0, 0, -10), notAfter: testNow.AddDate(0, 0, 80),
	})

	trusted := x509.NewCertPool()
	trusted.AddCert(root)

	tests := []struct {
		name       string
		chain      []*x509.Certificate
		roots      *x509.CertPool
		want       string
		wantExpiry string
	}{
		{"chains to a trusted root", []*x509.Certificate{current, inter}, trusted, TrustTrusted, ExpiryValid},
		{"root sent along with the chain", []*x509.Certificate{current, inter, root}, trusted, TrustTrusted, ExpiryValid},
		{"root not in the trust store", []*x509.Certificate{current, inter, root}, x509.NewCertPool(), TrustUntrusted, ExpiryValid},
		// Nothing is fetched to repair a chain, so a missing intermediate is
		// untrusted even though the root is known.
		{"intermediate left out", []*x509.Certificate{current}, trusted, TrustUntrusted, ExpiryValid},
		{"self-signed", []*x509.Certificate{selfSigned}, trusted, TrustUntrusted, ExpiryValid},
		// Expiry has its own verdict. A lapsed certificate from a trusted CA
		// must stay distinguishable from one no public CA ever issued.
		{"expired but from a trusted root", []*x509.Certificate{expired, inter}, trusted, TrustTrusted, ExpiryExpired},
		{"not yet valid but from a trusted root", []*x509.Certificate{notYetValid, inter}, trusted, TrustTrusted, ExpiryNotYetValid},
		{"expired and from an unknown root", []*x509.Certificate{expired, inter}, x509.NewCertPool(), TrustUntrusted, ExpiryExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := describeChain(tt.chain, "trust.test", tt.roots, Evidence{ProbedAt: testNow})
			if info.TrustVerdict != tt.want {
				t.Errorf("TrustVerdict = %q, want %q", info.TrustVerdict, tt.want)
			}
			if info.ExpiryVerdict != tt.wantExpiry {
				t.Errorf("ExpiryVerdict = %q, want %q", info.ExpiryVerdict, tt.wantExpiry)
			}
		})
	}
}

func TestDescribeChain_HostnameVerdict(t *testing.T) {
	withSANs, _ := makeCert(t, certSpec{
		cn: "example.test", key: ecdsaKey(t), dnsNames: []string{"example.test", "*.wild.test"},
		notBefore: testNow.AddDate(0, 0, -1), notAfter: testNow.AddDate(0, 0, 30),
	})
	commonNameOnly, _ := makeCert(t, certSpec{
		cn: "example.test", key: ecdsaKey(t),
		notBefore: testNow.AddDate(0, 0, -1), notAfter: testNow.AddDate(0, 0, 30),
	})

	tests := []struct {
		name string
		cert *x509.Certificate
		host string
		want string
	}{
		{"exact name", withSANs, "example.test", HostnameMatch},
		{"another name", withSANs, "other.test", HostnameMismatch},
		{"wildcard covers one label", withSANs, "a.wild.test", HostnameMatch},
		{"wildcard does not cover two labels", withSANs, "a.b.wild.test", HostnameMismatch},
		{"wildcard does not cover the bare name", withSANs, "wild.test", HostnameMismatch},
		// Clients stopped reading the common name years ago; a certificate
		// that only names the host there does not cover it.
		{"common name without a san", commonNameOnly, "example.test", HostnameMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := describeChain([]*x509.Certificate{tt.cert}, tt.host, x509.NewCertPool(), Evidence{ProbedAt: testNow})
			if info.HostnameVerdict != tt.want {
				t.Errorf("HostnameVerdict = %q, want %q", info.HostnameVerdict, tt.want)
			}
		})
	}
}
