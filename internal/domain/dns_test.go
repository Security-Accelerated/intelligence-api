package domain

import (
	"context"
	"net"
	"testing"
)

// These exercise LookupDNS against a loopback DNS server rather than the real
// internet. Previously they queried example.com and skipped on failure, which
// meant the assertions silently stopped running whenever the network was
// unavailable — coverage looked green while testing nothing.

func TestLookupDNS_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	info, err := LookupDNS(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
	if info != nil {
		t.Errorf("expected nil info for canceled context, got %+v", info)
	}
}

func TestLookupDNS_NonexistentDomain(t *testing.T) {
	addr, _ := startDNSServer(t, testZone{NXDOMAIN: true})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "this-domain-does-not-exist-xyz-42.invalid")
	if err == nil {
		t.Fatal("expected error for nonexistent domain, got nil")
	}
	if info != nil {
		t.Errorf("expected nil info for nonexistent domain, got %+v", info)
	}
}

func TestLookupDNS_CNAMEFiltersSelf(t *testing.T) {
	// A domain that is not a CNAME: the resolver reports the name itself, which
	// LookupDNS must filter out rather than report as a real CNAME.
	addr, _ := startDNSServer(t, testZone{
		A:     []string{"93.184.216.34"},
		CNAME: "example.com.",
	})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.CNAME != "" {
		t.Errorf("CNAME = %q, want empty — a self-referencing CNAME must be filtered", info.CNAME)
	}
}

func TestLookupDNS_RealCNAMEIsKept(t *testing.T) {
	// The complement of the test above: a CNAME pointing elsewhere is a genuine
	// record and must survive the self-reference filter.
	addr, _ := startDNSServer(t, testZone{
		A:     []string{"93.184.216.34"},
		CNAME: "target.example.net.",
	})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if info.CNAME != "target.example.net." {
		t.Errorf("CNAME = %q, want the real target preserved", info.CNAME)
	}
}

func TestLookupDNS_PartialSuccess(t *testing.T) {
	// Only A records exist; every other type comes back empty. The lookup must
	// still return what resolved rather than failing outright.
	addr, _ := startDNSServer(t, testZone{A: []string{"93.184.216.34"}})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if len(info.A) == 0 {
		t.Error("expected the A record that does exist")
	}
	if len(info.MX) != 0 || len(info.NS) != 0 || len(info.TXT) != 0 {
		t.Errorf("expected empty MX/NS/TXT, got %+v", info)
	}
}

func TestLookupDNS_IPv4And6Separation(t *testing.T) {
	addr, _ := startDNSServer(t, testZone{
		A:    []string{"93.184.216.34"},
		AAAA: []string{"2606:2800:220:1:248:1893:25c8:1946"},
	})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(info.A) == 0 || len(info.AAAA) == 0 {
		t.Fatalf("expected both A and AAAA, got %+v", info)
	}

	for _, a := range info.A {
		if ip := net.ParseIP(a); ip == nil || ip.To4() == nil {
			t.Errorf("A record contains non-IPv4 address: %q", a)
		}
	}
	for _, a := range info.AAAA {
		if ip := net.ParseIP(a); ip == nil || ip.To4() != nil {
			t.Errorf("AAAA record contains non-IPv6 address: %q", a)
		}
	}
}

func TestLookupDNS_AllRecordTypes(t *testing.T) {
	addr, _ := startDNSServer(t, testZone{
		A:    []string{"93.184.216.34"},
		AAAA: []string{"2606:2800:220:1:248:1893:25c8:1946"},
		MX:   []string{"10 mail.example.com."},
		NS:   []string{"a.iana-servers.net."},
		TXT:  []string{"v=spf1 -all"},
	})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(info.MX) != 1 || info.MX[0].Host != "mail.example.com." || info.MX[0].Priority != 10 {
		t.Errorf("MX = %+v, want one record host=mail.example.com. priority=10", info.MX)
	}
	if len(info.NS) != 1 || info.NS[0] != "a.iana-servers.net." {
		t.Errorf("NS = %v", info.NS)
	}
	if len(info.TXT) != 1 || info.TXT[0] != "v=spf1 -all" {
		t.Errorf("TXT = %v", info.TXT)
	}
}

func TestLookupDNS_NXDOMAINReturnsNilAndError(t *testing.T) {
	addr, _ := startDNSServer(t, testZone{NXDOMAIN: true})
	useLocalResolver(t, addr)

	info, err := LookupDNS(context.Background(), "guaranteed-nxdomain.invalid")
	if info != nil {
		t.Errorf("expected nil info for nxdomain, got %+v", info)
	}
	if err == nil {
		t.Error("expected error for nxdomain, got nil")
	}
}
