package main

import (
	"flag"
	"strings"
	"testing"
)

func testFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("lookups", "", "")
	fs.String("key", "", "")
	fs.Bool("json", false, "")
	return fs
}

// TestReorderArgs_FlagsAfterPositionals is the defect this exists for:
// `sactl lookup domain example.com --lookups dns` used the default lookup set
// and reported success, because flag parsing stops at the first positional.
func TestReorderArgs_FlagsAfterPositionals(t *testing.T) {
	fs := testFlagSet()
	got := reorderArgs(fs, []string{"example.com", "--lookups", "dns,ssl", "--json"})

	if err := fs.Parse(got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v := fs.Lookup("lookups").Value.String(); v != "dns,ssl" {
		t.Errorf("lookups = %q, want dns,ssl", v)
	}
	if fs.Lookup("json").Value.String() != "true" {
		t.Error("--json was not applied")
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "example.com" {
		t.Errorf("positional args = %v, want [example.com]", args)
	}
}

// TestReorderArgs_ValueNotStolen guards the subtle case: a flag's value must
// travel with it, or `--lookups dns` leaves dns behind as a lookup target.
func TestReorderArgs_ValueNotStolen(t *testing.T) {
	fs := testFlagSet()
	got := reorderArgs(fs, []string{"a.com", "--lookups", "dns", "b.com"})

	if err := fs.Parse(got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v := fs.Lookup("lookups").Value.String(); v != "dns" {
		t.Errorf("lookups = %q, want dns", v)
	}
	if args := strings.Join(fs.Args(), ","); args != "a.com,b.com" {
		t.Errorf("positional args = %q, want a.com,b.com", args)
	}
}

// TestReorderArgs_BoolFlagDoesNotConsume checks a bool flag leaves the next
// argument alone.
func TestReorderArgs_BoolFlagDoesNotConsume(t *testing.T) {
	fs := testFlagSet()
	got := reorderArgs(fs, []string{"--json", "a.com"})
	if err := fs.Parse(got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "a.com" {
		t.Errorf("positional args = %v, want [a.com]", args)
	}
}

func TestReorderArgs_EqualsForm(t *testing.T) {
	fs := testFlagSet()
	got := reorderArgs(fs, []string{"a.com", "--lookups=dns,ssl"})
	if err := fs.Parse(got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v := fs.Lookup("lookups").Value.String(); v != "dns,ssl" {
		t.Errorf("lookups = %q, want dns,ssl", v)
	}
}

// TestReorderArgs_DoubleDash keeps the escape hatch working: everything after
// -- is positional, even if it looks like a flag.
func TestReorderArgs_DoubleDash(t *testing.T) {
	fs := testFlagSet()
	got := reorderArgs(fs, []string{"--json", "--", "--not-a-flag"})
	if err := fs.Parse(got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if args := fs.Args(); len(args) != 1 || args[0] != "--not-a-flag" {
		t.Errorf("positional args = %v, want [--not-a-flag]", args)
	}
}

// TestReorderArgs_UnknownFlagStillRejected makes sure reordering does not
// swallow a typo that Parse should report.
func TestReorderArgs_UnknownFlagStillRejected(t *testing.T) {
	fs := testFlagSet()
	fs.SetOutput(new(strings.Builder))
	if err := fs.Parse(reorderArgs(fs, []string{"a.com", "--lookps", "dns"})); err == nil {
		t.Fatal("expected a parse error for an unknown flag")
	}
}
