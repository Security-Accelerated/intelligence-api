package domain

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// runTestDNSServer starts a local UDP DNS server and points the package's
// active resolver list at it for the duration of the test.
func runTestDNSServer(t *testing.T, handler dns.Handler) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()

	prev := activeDNSServers
	activeDNSServers = []string{pc.LocalAddr().String()}
	t.Cleanup(func() {
		activeDNSServers = prev
		_ = server.Shutdown()
	})
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func TestLookupDNSSecurity_SignedZoneWithCAA(t *testing.T) {
	runTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		switch req.Question[0].Qtype {
		case dns.TypeDS:
			m.Answer = append(m.Answer, mustRR(t, "example.com. 3600 IN DS 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C"))
		case dns.TypeDNSKEY:
			m.Answer = append(m.Answer, mustRR(t, "example.com. 3600 IN DNSKEY 257 3 8 AwEAAZ0aqu1rJ6orJynrRfNpPmayJZoAx9Ic2/Rl9VQWLMHyjxxem3VUSoNUIFXERQbj0A9Ogp0zDM9YIccKLRd6LmWiDCt7UJQxVdD+heb5Ec4qlqGmyX9MDabkvX2NvMwsUecbYBq8oXeTT9LRmCUt9KUt/WOi6DKECxoG/bWTykrXyBR8elD+SQY43OAVjlWrVltHxgp4/rhBCvRbmdflunaPIgu27eE2U4myDSLT8a4A0rB5uHG4PkOa9dIRs9y00M2mWf4lyPee7vi5few2dbayHXmieGcaAHrx76NGAABeY393xjlmDNcUkF1gpNWUla4fWZbbaYQzA93mLdrng+M="))
		case dns.TypeCAA:
			m.Answer = append(m.Answer,
				mustRR(t, `example.com. 3600 IN CAA 0 issue "letsencrypt.org"`),
				mustRR(t, `example.com. 3600 IN CAA 0 iodef "mailto:security@example.com"`),
			)
		}
		_ = w.WriteMsg(m)
	}))

	info, err := LookupDNSSecurity(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.DNSSEC == nil || !info.DNSSEC.Enabled {
		t.Fatalf("DNSSEC = %+v, want enabled", info.DNSSEC)
	}
	if info.DNSSEC.DSRecords != 1 || info.DNSSEC.DNSKEYRecords != 1 {
		t.Errorf("DS=%d DNSKEY=%d, want 1/1", info.DNSSEC.DSRecords, info.DNSSEC.DNSKEYRecords)
	}
	if len(info.DNSSEC.Algorithms) != 1 || info.DNSSEC.Algorithms[0] != "RSASHA256" {
		t.Errorf("algorithms = %v, want [RSASHA256]", info.DNSSEC.Algorithms)
	}
	if info.CAA == nil || !info.CAA.Present {
		t.Fatalf("CAA = %+v, want present", info.CAA)
	}
	if len(info.CAA.Records) != 2 {
		t.Fatalf("CAA records = %d, want 2", len(info.CAA.Records))
	}
	if info.CAA.Records[0].Tag != "issue" || info.CAA.Records[0].Value != "letsencrypt.org" {
		t.Errorf("CAA[0] = %+v, want issue/letsencrypt.org", info.CAA.Records[0])
	}
}

func TestLookupDNSSecurity_UnsignedZoneNoCAA(t *testing.T) {
	runTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req) // empty answer for every qtype
		_ = w.WriteMsg(m)
	}))

	info, err := LookupDNSSecurity(context.Background(), "unsigned.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.DNSSEC == nil || info.DNSSEC.Enabled {
		t.Errorf("DNSSEC = %+v, want present but disabled", info.DNSSEC)
	}
	if info.CAA == nil || info.CAA.Present {
		t.Errorf("CAA = %+v, want present=false", info.CAA)
	}
}

func TestLookupDNSSecurity_NXDomain(t *testing.T) {
	runTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	}))

	// NXDOMAIN is a valid answer: not signed, no CAA — not an error.
	info, err := LookupDNSSecurity(context.Background(), "nonexistent.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.DNSSEC.Enabled || info.CAA.Present {
		t.Errorf("expected empty results for NXDOMAIN, got %+v", info)
	}
}

func TestLookupDNSSecurity_ServerFailure(t *testing.T) {
	runTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}))

	if _, err := LookupDNSSecurity(context.Background(), "broken.example"); err == nil {
		t.Fatal("expected error on SERVFAIL from all resolvers")
	}
}
