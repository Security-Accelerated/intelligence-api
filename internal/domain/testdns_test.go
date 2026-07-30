package domain

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Shared DNS test harness. Nothing in the test suite should depend on external
// name servers: a test that fails when 8.8.8.8 has a bad second teaches you to
// ignore red, and these tests exist to exercise our own logic rather than to
// monitor Google's uptime. Everything here binds loopback only, so the suite
// passes with no network access at all.

// testZone is the set of answers a fake server hands out. A nil field means the
// server answers that query type with an empty NOERROR reply, which is how a
// real resolver reports "no records of this type".
type testZone struct {
	A     []string
	AAAA  []string
	MX    []string // "10 mail.example.com."
	NS    []string
	TXT   []string
	CNAME string
	// NXDOMAIN makes every query return NameError regardless of the above.
	NXDOMAIN bool
}

// startDNSServer runs a loopback UDP DNS server answering from zone, and
// returns its address plus a counter of queries received.
func startDNSServer(t *testing.T, zone testZone) (string, *atomic.Int32) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var hits atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(req)

		if zone.NXDOMAIN {
			m.SetRcode(req, dns.RcodeNameError)
			_ = w.WriteMsg(m)
			return
		}
		if len(req.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}

		name := req.Question[0].Name
		addFor := func(owner, format string, values ...string) {
			for _, v := range values {
				if rr, err := dns.NewRR(owner + " 60 IN " + format + " " + v); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		add := func(format string, values ...string) { addFor(name, format, values...) }

		// aliased reports whether name is the owner of the zone's CNAME. Such a
		// name has no records of its own (RFC 1034 §3.6.2), so address queries
		// for it must be answered with the CNAME followed by the target's
		// records rather than with a bare A. This is not pedantry: Go's
		// LookupCNAME takes the canonical name from the address responses, not
		// from the CNAME query, so a zone that serves both a CNAME and a direct
		// A for one name gives an answer that varies with query ordering.
		aliased := zone.CNAME != "" && name != zone.CNAME

		switch req.Question[0].Qtype {
		case dns.TypeA:
			if aliased {
				add("CNAME", zone.CNAME)
				addFor(zone.CNAME, "A", zone.A...)
			} else {
				add("A", zone.A...)
			}
		case dns.TypeAAAA:
			if aliased {
				add("CNAME", zone.CNAME)
				addFor(zone.CNAME, "AAAA", zone.AAAA...)
			} else {
				add("AAAA", zone.AAAA...)
			}
		case dns.TypeMX:
			add("MX", zone.MX...)
		case dns.TypeNS:
			add("NS", zone.NS...)
		case dns.TypeTXT:
			for _, txt := range zone.TXT {
				if rr, err := dns.NewRR(name + ` 60 IN TXT "` + txt + `"`); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeCNAME:
			// Only the original owner has the CNAME. Answering for every name
			// would make the target point at itself, and Go's LookupCNAME
			// follows the chain — it would loop rather than settle on a
			// canonical name.
			if zone.CNAME != "" && name != zone.CNAME {
				add("CNAME", zone.CNAME)
			}
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return pc.LocalAddr().String(), &hits
}

// startBlackholeDNS binds a UDP socket that accepts packets and never replies.
// This is the failure a dial-time failover loop cannot detect: the address is
// routable, so the "connection" succeeds and only the absent answer reveals it.
func startBlackholeDNS(t *testing.T) (string, *atomic.Int32) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var hits atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			hits.Add(1) // received, deliberately never answered
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })

	return pc.LocalAddr().String(), &hits
}

// useLocalResolver points the lookup resolver at servers for the duration of
// the test, mirroring what InitResolver does in production, and restores it
// afterwards. Lookups that go through domain.Resolver() (LookupDNS, BGP,
// reputation, reverse DNS) then resolve against a server the test controls.
//
// Note this leaves net.DefaultResolver alone: overriding the global is exactly
// the bug this indirection exists to prevent.
func useLocalResolver(t *testing.T, servers ...string) {
	t.Helper()

	prev := externalResolver.Load()
	externalResolver.Store(NewExternalResolver(servers, 2*time.Second))
	t.Cleanup(func() { externalResolver.Store(prev) })
}
