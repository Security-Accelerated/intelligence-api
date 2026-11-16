package domain

import (
	"context"
	"crypto/tls"
	"fmt"
)

// probedGroups are the key exchange groups a lookup offers, post-quantum
// first. Names are the IANA "TLS Supported Groups" names, which is what other
// tools and server configurations call them. The list is every group the
// standard library implements; a group it cannot speak cannot be probed.
var probedGroups = []struct {
	id          tls.CurveID
	name        string
	postQuantum bool
}{
	{tls.X25519MLKEM768, "X25519MLKEM768", true},
	{tls.SecP256r1MLKEM768, "SecP256r1MLKEM768", true},
	{tls.SecP384r1MLKEM1024, "SecP384r1MLKEM1024", true},
	{tls.MLKEM1024, "MLKEM1024", true},
	{tls.X25519, "x25519", false},
	{tls.CurveP256, "secp256r1", false},
	{tls.CurveP384, "secp384r1", false},
	{tls.CurveP521, "secp521r1", false},
}

// LookupKeyExchange reports which key exchange groups host accepts on port
// 443, and whether any of them is post-quantum.
func LookupKeyExchange(ctx context.Context, host string) (*KeyExchangeInfo, error) {
	s, err := newSession(ctx, host)
	if err != nil {
		return nil, err
	}
	return probeKeyExchange(ctx, s)
}

// probeKeyExchange offers each group on its own, then all of them together to
// see which one the server picks.
//
// The cipher suites are left at the standard library's defaults, which are all
// ECDHE. Offering RSA key exchange here would let a TLS 1.2 server complete the
// handshake without using the group at all. The negotiated group is checked
// against the one offered for the same reason.
//
// A server with no forward-secret key exchange left accepts none of these and
// reports ErrNoHandshake. That is rare enough to leave as a failed lookup.
func probeKeyExchange(ctx context.Context, s *session) (*KeyExchangeInfo, error) {
	info := &KeyExchangeInfo{Evidence: s.evidence(), Verdict: KeyExchangeClassical}
	anyAccepted := false

	for _, g := range probedGroups {
		state, accepted, err := s.offer(ctx, &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{g.id},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.name, err)
		}
		accepted = accepted && state.CurveID == g.id

		info.Groups = append(info.Groups, KeyExchangeGroup{
			Name:        g.name,
			Accepted:    accepted,
			PostQuantum: g.postQuantum,
		})
		if accepted {
			anyAccepted = true
			if g.postQuantum {
				info.Verdict = KeyExchangePostQuantum
			}
		}
	}

	if !anyAccepted {
		return nil, ErrNoHandshake
	}

	// A refusal here is left as an empty Negotiated rather than failing the
	// lookup: the per-group answers above are already complete.
	state, accepted, err := s.offer(ctx, &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: everyGroup(),
	})
	if err != nil {
		return nil, fmt.Errorf("combined offer: %w", err)
	}
	if accepted {
		info.Negotiated = groupName(state.CurveID)
	}

	return info, nil
}

// groupName returns the IANA name for a probed group, or "" for anything else.
func groupName(id tls.CurveID) string {
	for _, g := range probedGroups {
		if g.id == id {
			return g.name
		}
	}
	return ""
}
