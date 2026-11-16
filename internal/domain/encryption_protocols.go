package domain

import (
	"context"
	"crypto/tls"
	"fmt"
)

// probedVersions are the protocol versions a lookup offers, newest first.
// SSL 3.0 and earlier are absent because the standard library cannot speak
// them; a server that accepts only those reports ErrNoHandshake.
var probedVersions = []struct {
	id   uint16
	name string
}{
	{tls.VersionTLS13, "TLS 1.3"},
	{tls.VersionTLS12, "TLS 1.2"},
	{tls.VersionTLS11, "TLS 1.1"},
	{tls.VersionTLS10, "TLS 1.0"},
}

// LookupProtocols reports which TLS versions host accepts on port 443.
func LookupProtocols(ctx context.Context, host string) (*ProtocolsInfo, error) {
	s, err := newSession(ctx, host)
	if err != nil {
		return nil, err
	}
	return probeProtocols(ctx, s)
}

// probeProtocols offers each version on its own, one handshake per version.
// Offering a range would only show which version the server prefers.
func probeProtocols(ctx context.Context, s *session) (*ProtocolsInfo, error) {
	info := &ProtocolsInfo{Evidence: s.evidence()}
	anyAccepted := false

	for _, v := range probedVersions {
		_, accepted, err := s.offer(ctx, &tls.Config{
			// Deliberately reaches down to TLS 1.0 with every cipher suite:
			// finding out whether the server still accepts them is the lookup.
			// Every group too, so the answer is about the version and not
			// about which key exchange the server happens to require.
			MinVersion:       v.id,
			MaxVersion:       v.id,
			CipherSuites:     everyCipherSuite(),
			CurvePreferences: everyGroup(),
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", v.name, err)
		}
		info.Versions = append(info.Versions, ProtocolVersion{Name: v.name, Accepted: accepted})
		if accepted {
			anyAccepted = true
			if v.id == tls.VersionTLS10 || v.id == tls.VersionTLS11 {
				info.LegacyAccepted = true
			}
		}
	}

	if !anyAccepted {
		return nil, ErrNoHandshake
	}
	return info, nil
}
