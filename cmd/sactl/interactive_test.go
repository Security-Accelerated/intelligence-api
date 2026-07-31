package main

import (
	"context"
	"strings"
	"testing"
)

// drive runs the shell against a scripted sequence of answers and returns
// everything it printed.
func drive(t *testing.T, input string) string {
	t.Helper()
	var out strings.Builder
	sh := newShell(strings.NewReader(input), &out)
	defer sh.close()
	if err := sh.runShell(context.Background()); err != nil {
		t.Fatalf("shell returned an error: %v", err)
	}
	return out.String()
}

func TestShell_QuitsCleanly(t *testing.T) {
	out := drive(t, "q\n")
	if !strings.Contains(out, "Main menu") {
		t.Errorf("main menu was not shown:\n%s", out)
	}
	if !strings.Contains(out, "Bye.") {
		t.Errorf("did not acknowledge quitting:\n%s", out)
	}
}

// TestShell_EOFQuits covers Ctrl-D and, more importantly, a closed pipe. A
// prompt loop that treats EOF as an empty answer spins forever printing menus.
func TestShell_EOFQuits(t *testing.T) {
	out := drive(t, "")
	if strings.Count(out, "Main menu") > 1 {
		t.Errorf("menu redrew after EOF instead of exiting:\n%s", out)
	}
}

func TestShell_UnknownOptionDoesNotExit(t *testing.T) {
	out := drive(t, "99\nq\n")
	if !strings.Contains(out, `Unknown option "99"`) {
		t.Errorf("no complaint about the bad option:\n%s", out)
	}
	if strings.Count(out, "Main menu") < 2 {
		t.Errorf("menu should redraw after a bad option:\n%s", out)
	}
}

func TestShell_SubmenuBackReturnsToMain(t *testing.T) {
	out := drive(t, "1\nb\nq\n")
	if !strings.Contains(out, "Customers") {
		t.Errorf("customers submenu not shown:\n%s", out)
	}
	if strings.Count(out, "Main menu") < 2 {
		t.Errorf("'b' should return to the main menu:\n%s", out)
	}
}

// TestShell_QuitFromSubmenu checks that q unwinds the whole stack rather than
// only the innermost menu.
func TestShell_QuitFromSubmenu(t *testing.T) {
	out := drive(t, "1\nq\n")
	if !strings.Contains(out, "Bye.") {
		t.Errorf("q inside a submenu should exit the shell:\n%s", out)
	}
}

// TestShell_ActionErrorDoesNotExit is the important one for day-to-day use: a
// mistyped ID or an unreachable database must leave the operator in the menu,
// not dump them back to their shell mid-task.
func TestShell_ActionErrorDoesNotExit(t *testing.T) {
	var out strings.Builder
	// No database is configured in the test environment, so any customer action
	// fails to connect. Choosing "Customers > List" then quitting must still
	// reach the goodbye.
	sh := newShell(strings.NewReader("1\n1\nb\nq\n"), &out)
	sh.db.databaseURL = "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
	defer sh.close()

	if err := sh.runShell(context.Background()); err != nil {
		t.Fatalf("shell returned an error: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "error:") {
		t.Errorf("connection failure was not reported:\n%s", got)
	}
	if !strings.Contains(got, "Bye.") {
		t.Errorf("shell exited early instead of returning to the menu:\n%s", got)
	}
}

func TestShell_SettingsChangeHost(t *testing.T) {
	out := drive(t, "7\n1\nhttp://localhost:8080\nb\nq\n")
	if !strings.Contains(out, "API host is now http://localhost:8080") {
		t.Errorf("host change not applied:\n%s", out)
	}
}

func TestAskYesNo_DefaultsToNo(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"y\n", true}, {"Y\n", true}, {"yes\n", true},
		{"\n", false}, {"n\n", false}, {"anything\n", false},
	} {
		var out strings.Builder
		sh := newShell(strings.NewReader(tc.in), &out)
		got, err := sh.askYesNo("go?")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != tc.want {
			t.Errorf("askYesNo(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAskChoice_RejectsUnknownThenAccepts(t *testing.T) {
	var out strings.Builder
	sh := newShell(strings.NewReader("enterprise\npro\n"), &out)
	got, err := sh.askChoice("  Plan", []string{"free", "pro"}, "free")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "pro" {
		t.Errorf("got %q, want pro", got)
	}
	if !strings.Contains(out.String(), "Choose one of") {
		t.Errorf("did not reprompt on an invalid choice:\n%s", out.String())
	}
}

func TestAskInt_RejectsNonPositive(t *testing.T) {
	var out strings.Builder
	sh := newShell(strings.NewReader("abc\n0\n-3\n7\n"), &out)
	got, err := sh.askInt("  ID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 7 {
		t.Errorf("got %d, want 7", got)
	}
}
