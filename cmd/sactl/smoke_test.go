package main

import (
	"strings"
	"testing"
)

func poolOf(keys ...string) smokeKeys {
	return smokeKeys{pools: map[string]*keyPool{"free": {keys: keys}}}
}

// TestKeyPool_RotatesToSpreadLoad is the reason the pool exists: the limiter is
// per key per minute, so handing out the same key repeatedly would exhaust one
// window while the others sat idle.
func TestKeyPool_RotatesToSpreadLoad(t *testing.T) {
	k := poolOf("a", "b", "c")
	got := []string{k.forPlan("free"), k.forPlan("free"), k.forPlan("free"), k.forPlan("free")}
	want := []string{"a", "b", "c", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rotation = %v, want %v", got, want)
		}
	}
}

// TestKeyPool_PinnedIgnoresRotation guards the rate limit check. Rotation is
// exactly what must not happen there: with three keys, twelve rotating requests
// are four per key and never reach a 5/minute limit, so the check would pass
// while testing nothing.
// TestKeyPool_Retire and the pinned-key helper were replaced by a reserved key;
// see TestResolveSmokeKeys_ReservedKeyHeldOutOfPool.

func TestKeyPool_EmptyPool(t *testing.T) {
	k := poolOf()
	if k.have("free") || k.count("free") != 0 {
		t.Error("an empty pool should report no keys")
	}
	if k.forPlan("free") != "" {
		t.Error("an empty pool should hand out nothing")
	}
}

// TestResolveSmokeKeys_ReservedKeyHeldOutOfPool is the property the rate limit
// check depends on. If the reserved key were also in rotation, exhausting its
// window would stall whichever later check happened to draw it — a failure that
// would look like the service being slow rather than the suite eating its own
// budget.
func TestResolveSmokeKeys_ReservedKeyHeldOutOfPool(t *testing.T) {
	t.Setenv("SMOKE_FREE_KEY", "pool-a")
	t.Setenv("SMOKE_FREE_KEY_2", "reserved")
	t.Setenv("SMOKE_FREE_KEY_3", "pool-b")
	t.Setenv("SMOKE_RATELIMIT_KEY", "reserved")
	for _, plan := range []string{"basic", "pro", "admin"} {
		t.Setenv("SMOKE_"+strings.ToUpper(plan)+"_KEY", "")
	}

	keys := resolveSmokeKeys(&smokeFlags{})

	if keys.rateLimit != "reserved" {
		t.Fatalf("rateLimit = %q, want reserved", keys.rateLimit)
	}
	if n := keys.count("free"); n != 2 {
		t.Errorf("free pool has %d keys, want 2 (the reserved one excluded)", n)
	}
	// Exclusion must hold even though the same value was also listed as a
	// free key — that is exactly how an operator would configure it by hand.
	for i := 0; i < 6; i++ {
		if got := keys.forPlan("free"); got == "reserved" {
			t.Fatalf("the reserved key was handed out by rotation on call %d", i)
		}
	}
}

func TestResolveSmokeKeys_NoReservedKey(t *testing.T) {
	t.Setenv("SMOKE_FREE_KEY", "pool-a")
	t.Setenv("SMOKE_FREE_KEY_2", "")
	t.Setenv("SMOKE_FREE_KEY_3", "")
	t.Setenv("SMOKE_RATELIMIT_KEY", "")

	keys := resolveSmokeKeys(&smokeFlags{})
	if keys.rateLimit != "" {
		t.Errorf("rateLimit = %q, want empty", keys.rateLimit)
	}
	if n := keys.count("free"); n != 1 {
		t.Errorf("free pool has %d keys, want 1", n)
	}
}

// TestResolveSmokeKeys_FlagBeatsEnv keeps the override working, since an
// operator pointing at a different environment must not be silently overridden
// by whatever .env happened to contain.
func TestResolveSmokeKeys_FlagBeatsEnv(t *testing.T) {
	t.Setenv("SMOKE_RATELIMIT_KEY", "from-env")
	keys := resolveSmokeKeys(&smokeFlags{rateLimitKey: "  from-flag  "})
	if keys.rateLimit != "from-flag" {
		t.Errorf("rateLimit = %q, want the trimmed flag value", keys.rateLimit)
	}
}
