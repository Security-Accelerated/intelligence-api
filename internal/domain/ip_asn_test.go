package domain

import "testing"

func TestCymruOriginName(t *testing.T) {
	tests := []struct {
		ip      string
		want    string
		wantErr bool
	}{
		{ip: "8.8.8.8", want: "8.8.8.8.origin.asn.cymru.com"},
		{ip: "192.0.2.10", want: "10.2.0.192.origin.asn.cymru.com"},
		// IPv4-mapped IPv6 is an IPv4 address and must use the IPv4 zone.
		{ip: "::ffff:192.0.2.10", want: "10.2.0.192.origin.asn.cymru.com"},
		{
			ip:   "2001:4860:4860::8888",
			want: "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com",
		},
		{ip: "not-an-ip", wantErr: true},
	}
	for _, tt := range tests {
		got, err := cymruOriginName(tt.ip)
		if (err != nil) != tt.wantErr {
			t.Errorf("cymruOriginName(%q) err = %v, wantErr %v", tt.ip, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("cymruOriginName(%q) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestTrimCountrySuffix(t *testing.T) {
	tests := []struct{ in, want string }{
		{"GOOGLE - Google LLC, US", "GOOGLE - Google LLC"},
		{"GOOGLE, US", "GOOGLE"},
		{"CLOUDFLARENET, US", "CLOUDFLARENET"},
		{"AMAZON-02, US", "AMAZON-02"},
		// A comma inside the name stays; only a trailing two-letter code goes.
		{"Hetzner Online GmbH, DE", "Hetzner Online GmbH"},
		{"Foo, Inc", "Foo, Inc"},
		{"NO-COUNTRY", "NO-COUNTRY"},
		{"lower, us", "lower, us"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := trimCountrySuffix(tt.in); got != tt.want {
			t.Errorf("trimCountrySuffix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
