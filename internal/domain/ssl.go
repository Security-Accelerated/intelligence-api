package domain

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/safenet"
)

func LookupSSL(ctx context.Context, domain string) (*SSLInfo, error) {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true,
		},
		NetDialer: safenet.SafeDialer(10 * time.Second),
	}

	conn, err := dialer.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return nil, fmt.Errorf("tls connect: %w", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a tls connection")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	daysUntilExpiry := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))

	return &SSLInfo{
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SANs:               cert.DNSNames,
		SerialNumber:       cert.SerialNumber.Text(16),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Expired:            now.After(cert.NotAfter),
		DaysUntilExpiry:    daysUntilExpiry,
	}, nil
}
