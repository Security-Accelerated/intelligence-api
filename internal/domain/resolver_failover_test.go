package domain

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// answeringServer starts a local UDP DNS server that answers A queries with ip,
// and returns its address plus a counter of queries it received.
func answeringServer(t *testing.T, ip string) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var hits atomic.Int32
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), &hits
}

// blackholeServer binds a UDP socket that accepts packets and never replies —
// the failure mode that a dial-time failover loop cannot detect, because the
// address is routable and the "connection" succeeds.
func blackholeServer(t *testing.T) (string, *atomic.Int32) {
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

func TestFailover_BlackholedFirstServer(t *testing.T) {
	prev := DefaultDNSPerServerTimeout
	DefaultDNSPerServerTimeout = 150 * time.Millisecond
	t.Cleanup(func() { DefaultDNSPerServerTimeout = prev })

	dead, deadHits := blackholeServer(t)
	live, liveHits := answeringServer(t, "203.0.113.10")

	r := NewExternalResolver([]string{dead, live}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com.")
	if err != nil {
		t.Fatalf("expected failover to the second server, got: %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "203.0.113.10" {
		t.Errorf("addrs = %v, want the second server's answer", addrs)
	}
	if deadHits.Load() == 0 {
		t.Error("the blackholed server was never tried — failover order is wrong")
	}
	if liveHits.Load() == 0 {
		t.Error("the live server was never reached")
	}
}

func TestFailover_FirstServerAnswers_NoSecondQuery(t *testing.T) {
	live, liveHits := answeringServer(t, "203.0.113.1")
	unused, unusedHits := answeringServer(t, "203.0.113.2")

	r := NewExternalResolver([]string{live, unused}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com.")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "203.0.113.1" {
		t.Errorf("addrs = %v, want the first server's answer", addrs)
	}
	if liveHits.Load() == 0 {
		t.Error("first server was not queried")
	}
	if n := unusedHits.Load(); n != 0 {
		t.Errorf("second server queried %d times; a healthy first server must not fan out", n)
	}
}

func TestFailover_AllServersBlackholed(t *testing.T) {
	prev := DefaultDNSPerServerTimeout
	DefaultDNSPerServerTimeout = 100 * time.Millisecond
	t.Cleanup(func() { DefaultDNSPerServerTimeout = prev })

	a, aHits := blackholeServer(t)
	b, bHits := blackholeServer(t)

	r := NewExternalResolver([]string{a, b}, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := r.LookupHost(ctx, "example.com."); err == nil {
		t.Fatal("expected an error when every server is silent")
	}
	if aHits.Load() == 0 || bHits.Load() == 0 {
		t.Errorf("both servers should have been tried; got a=%d b=%d", aHits.Load(), bHits.Load())
	}
}

func TestFailover_BoundedByCallerDeadline(t *testing.T) {
	prev := DefaultDNSPerServerTimeout
	DefaultDNSPerServerTimeout = 5 * time.Second // deliberately longer than the caller's budget
	t.Cleanup(func() { DefaultDNSPerServerTimeout = prev })

	dead, _ := blackholeServer(t)
	r := NewExternalResolver([]string{dead, dead}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := r.LookupHost(ctx, "example.com."); err == nil {
		t.Fatal("expected an error")
	}
	// The per-server timeout must never override the caller's deadline.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v; caller deadline of 300ms was not respected", elapsed)
	}
}

func TestFailover_SingleServerStillWorks(t *testing.T) {
	live, _ := answeringServer(t, "203.0.113.5")
	r := NewExternalResolver([]string{live}, 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "example.com.")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(addrs) == 0 || addrs[0] != "203.0.113.5" {
		t.Errorf("addrs = %v", addrs)
	}
}
