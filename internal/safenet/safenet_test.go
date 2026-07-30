package safenet

import (
	"errors"
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Should block
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.0.1", true},
		{"169.254.169.254", true}, // link-local / cloud metadata
		{"0.0.0.0", true},
		{"224.0.0.1", true},       // multicast
		{"100.64.0.1", true},      // CGNAT
		{"::1", true},             // IPv6 loopback
		{"fc00::1", true},         // IPv6 unique local
		{"fe80::1", true},         // IPv6 link-local
		{"100.127.255.255", true}, // CGNAT upper boundary
		{"0.255.255.255", true},   // "this network" 0.0.0.0/8
		{"192.0.0.8", true},       // IETF protocol assignments
		{"192.0.2.1", true},       // TEST-NET-1
		{"198.51.100.42", true},   // TEST-NET-2
		{"203.0.113.99", true},    // TEST-NET-3
		{"198.18.0.1", true},      // benchmarking 198.18.0.0/15
		{"198.19.255.255", true},  // benchmarking upper boundary
		{"240.0.0.1", true},       // reserved 240.0.0.0/4
		{"255.255.255.254", true}, // reserved 240.0.0.0/4 upper range
		{"2001:db8::1", true},     // IPv6 documentation
		{"::ffff:10.0.0.1", true}, // IPv4-mapped IPv6 must not bypass v4 rules
		{"::ffff:192.0.2.1", true},
		{"239.255.255.255", true}, // multicast top

		// Should allow
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"100.63.255.255", false}, // just below CGNAT
		{"100.128.0.0", false},    // just above CGNAT
		{"172.15.255.255", false}, // just below 172.16.0.0/12
		{"172.32.0.0", false},     // just above 172.31.255.255
		{"2606:4700::1", false},   // public IPv6
		{"198.17.255.255", false}, // just below benchmarking range
		{"198.20.0.0", false},     // just above benchmarking range
		{"192.0.3.1", false},      // just above TEST-NET-1
		{"203.0.114.0", false},    // just above TEST-NET-3
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			if got := IsPrivateIP(ip); got != tt.want {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestDialControl_BlocksPrivate(t *testing.T) {
	blocked := []string{
		"127.0.0.1:80",
		"10.0.0.1:443",
		"169.254.169.254:80",
		"[::1]:80",
	}
	for _, addr := range blocked {
		t.Run("block_"+addr, func(t *testing.T) {
			err := DialControl("tcp", addr, nil)
			if err == nil {
				t.Fatalf("DialControl(%q) = nil, want error", addr)
			}
			var blocked *BlockedError
			if !errors.As(err, &blocked) {
				t.Errorf("DialControl(%q) error type = %T, want *BlockedError", addr, err)
			}
		})
	}
}

func TestDialControl_AllowsPublic(t *testing.T) {
	allowed := []string{
		"8.8.8.8:53",
		"93.184.216.34:443",
		"[2606:4700::1]:443",
	}
	for _, addr := range allowed {
		t.Run("allow_"+addr, func(t *testing.T) {
			if err := DialControl("tcp", addr, nil); err != nil {
				t.Errorf("DialControl(%q) = %v, want nil", addr, err)
			}
		})
	}
}
