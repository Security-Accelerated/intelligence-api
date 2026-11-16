package domain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"time"
)

// LookupCertificate reports the certificate chain host presents on port 443:
// the algorithms each certificate uses, when the leaf expires, whether the
// chain leads to a publicly trusted root, and whether the leaf covers host.
func LookupCertificate(ctx context.Context, host string) (*CertificateInfo, error) {
	s, err := newSession(ctx, host)
	if err != nil {
		return nil, err
	}
	return probeCertificate(ctx, s)
}

// probeCertificate makes one handshake, as permissive as the client can be,
// and describes the chain the server sent. This is the chain a client with
// current defaults receives; a server holding both an RSA and an ECDSA
// certificate picks one per connection.
func probeCertificate(ctx context.Context, s *session) (*CertificateInfo, error) {
	// Down to TLS 1.0 with every cipher suite, so that a server too old for
	// current defaults still gets its certificate reported, and with every
	// group, so that one requiring a key exchange outside those defaults does
	// too.
	//nolint:gosec // G402: reaching legacy servers is the feature.
	state, err := s.handshake(ctx, &tls.Config{
		MinVersion:       tls.VersionTLS10,
		CipherSuites:     everyCipherSuite(),
		CurvePreferences: everyGroup(),
	})
	if err != nil {
		var rejected *rejectedError
		if errors.As(err, &rejected) {
			return nil, ErrNoHandshake
		}
		return nil, err
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server presented no certificate")
	}
	return describeChain(state.PeerCertificates, s.host, s.roots, s.evidence()), nil
}

// describeChain builds the certificate payload from a chain, leaf first. Split
// from the handshake so the verdict rules can be tested on certificates built
// in memory. roots is the trust store for the trust verdict; nil means the
// system roots.
func describeChain(chain []*x509.Certificate, host string, roots *x509.CertPool, ev Evidence) *CertificateInfo {
	leaf := chain[0]
	info := &CertificateInfo{
		Evidence:        ev,
		SANs:            leaf.DNSNames,
		DaysUntilExpiry: int(math.Floor(leaf.NotAfter.Sub(ev.ProbedAt).Hours() / 24)),
		ValidityDays:    int(math.Round(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)),
		ExpiryVerdict:   expiryVerdict(leaf, ev.ProbedAt),
		TrustVerdict:    trustVerdict(chain, roots, ev.ProbedAt),
		HostnameVerdict: hostnameVerdict(leaf, host),
	}

	strength := strengthPostQuantum
	for _, cert := range chain {
		selfSigned := isSelfSigned(cert)
		info.Chain = append(info.Chain, ChainCertificate{
			Subject:            displayName(cert.Subject.CommonName, cert.Subject.String()),
			Issuer:             displayName(cert.Issuer.CommonName, cert.Issuer.String()),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
			KeyBits:            keyBits(cert),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			SelfSigned:         selfSigned,
		})

		strength = min(strength, keyStrength(cert))
		// A self-signed certificate's signature is made with its own key and
		// protects nothing: a trust anchor is trusted by being installed, not
		// by its signature. Old roots signed with SHA-1 are not a weakness.
		if !selfSigned {
			strength = min(strength, signatureStrength(cert.SignatureAlgorithm))
		}
	}
	info.AlgorithmVerdict = strength.verdict()

	return info
}

// isSelfSigned reports whether cert was signed with its own key. Matching
// subject and issuer names only make a certificate self-issued: a CA rolling
// over to a new key can publish a certificate with the same name on both
// sides, signed by the old key. That one is an ordinary link in the chain and
// its signature has to be scored like any other.
//
// When the signature cannot be checked at all (an algorithm the standard
// library refuses, such as MD5, or does not implement), the names are all
// there is to go on, and the certificate is treated as self-signed as before.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		return true
	}
	var insecure x509.InsecureAlgorithmError
	return errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm)
}

// algorithmStrength orders the algorithm verdicts so a chain can be scored by
// its weakest part.
type algorithmStrength int

const (
	strengthWeak algorithmStrength = iota
	strengthUnknown
	strengthClassical
	strengthPostQuantum
)

func (s algorithmStrength) verdict() string {
	switch s {
	case strengthWeak:
		return AlgorithmsWeak
	case strengthClassical:
		return AlgorithmsClassical
	case strengthPostQuantum:
		return AlgorithmsPostQuantum
	default:
		return AlgorithmsUnknown
	}
}

// keyStrength scores a certificate's public key. The size floors are the ones
// public CAs have enforced for years: 2048-bit RSA and 224-bit elliptic curves.
func keyStrength(cert *x509.Certificate) algorithmStrength {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if keyBits(cert) < 2048 {
			return strengthWeak
		}
		return strengthClassical
	case x509.ECDSA:
		if keyBits(cert) < 224 {
			return strengthWeak
		}
		return strengthClassical
	case x509.Ed25519:
		return strengthClassical
	case x509.DSA:
		return strengthWeak
	case x509.MLDSA:
		return strengthPostQuantum
	default:
		return strengthUnknown
	}
}

// signatureStrength scores the algorithm a certificate was signed with.
func signatureStrength(alg x509.SignatureAlgorithm) algorithmStrength {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.DSAWithSHA1, x509.DSAWithSHA256, x509.ECDSAWithSHA1:
		return strengthWeak
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return strengthPostQuantum
	case x509.UnknownSignatureAlgorithm:
		return strengthUnknown
	default:
		return strengthClassical
	}
}

// keyBits returns the public key size in bits, or 0 when it has no single
// meaningful size to report.
func keyBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func expiryVerdict(leaf *x509.Certificate, now time.Time) string {
	switch {
	case now.Before(leaf.NotBefore):
		return ExpiryNotYetValid
	case now.After(leaf.NotAfter):
		return ExpiryExpired
	default:
		return ExpiryValid
	}
}

// trustVerdict reports whether the chain leads to a root in roots, using the
// certificates the server sent as intermediates. Nothing is fetched: a server
// that leaves out an intermediate is untrusted here even though some browsers
// would repair the chain, because a strict client fails on it.
//
// The chain is judged at a moment inside the leaf's validity window: now when
// the leaf is current, otherwise the nearest end of the window. Expiry has its
// own verdict, and folding it in here would make every expired certificate
// untrusted as well, hiding the difference between "renewal was missed" and
// "this was never issued by a public CA".
//
// The verification error is deliberately dropped. It is an answer about the
// target, reported as data, and must never come back as the lookup's error:
// IsExpectedError treats x509 failures as ours.
func trustVerdict(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) string {
	leaf := chain[0]
	at := now
	if at.Before(leaf.NotBefore) {
		at = leaf.NotBefore
	} else if at.After(leaf.NotAfter) {
		at = leaf.NotAfter
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	// No DNSName: the hostname has its own verdict.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
	}); err != nil {
		return TrustUntrusted
	}
	return TrustTrusted
}

// hostnameVerdict reports whether the leaf covers host, by the rules a browser
// applies: subject alternative names only, wildcards one label deep.
func hostnameVerdict(leaf *x509.Certificate, host string) string {
	if leaf.VerifyHostname(host) != nil {
		return HostnameMismatch
	}
	return HostnameMatch
}

// displayName prefers a certificate's common name and falls back to the full
// distinguished name for certificates issued without one.
func displayName(commonName, full string) string {
	if commonName != "" {
		return commonName
	}
	return full
}
