package billing

import "strings"

// Stripe key modes as reported on /v1/info and in the startup log.
const (
	ModeLive    = "live"
	ModeTest    = "test"
	ModeUnknown = "unknown"
)

// KeyMode reports whether a Stripe secret key is a live or test key, from its
// prefix. Stripe issues standard keys as sk_live_/sk_test_ and restricted keys
// as rk_live_/rk_test_. Nothing else in the billing path distinguishes the two
// modes: a test key, a test webhook secret, and a test price ID all work
// together in production and take no money, so the mode is surfaced where an
// operator will see it rather than inferred from a failed checkout.
func KeyMode(secretKey string) string {
	switch {
	case strings.HasPrefix(secretKey, "sk_live_"), strings.HasPrefix(secretKey, "rk_live_"):
		return ModeLive
	case strings.HasPrefix(secretKey, "sk_test_"), strings.HasPrefix(secretKey, "rk_test_"):
		return ModeTest
	default:
		return ModeUnknown
	}
}
