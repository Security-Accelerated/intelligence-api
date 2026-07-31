package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRepoRoot_WalksUp lets the command work from any subdirectory rather than
// only the checkout root.
func TestRepoRoot_WalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "docker-compose.yaml"), []byte("services:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "internal", "handler")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(nested)

	got, err := repoRoot()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// macOS resolves temp dirs through a symlink, so compare resolved paths.
	wantResolved, _ := filepath.EvalSymlinks(root)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != wantResolved {
		t.Errorf("repoRoot = %q, want %q", gotResolved, wantResolved)
	}
}

// TestRepoRoot_NotFound must name what is missing. Without it the failure
// surfaces later inside docker as a message about no configuration file, which
// does not point at the actual mistake of running from the wrong directory.
func TestRepoRoot_NotFound(t *testing.T) {
	t.Chdir(t.TempDir())

	_, err := repoRoot()
	if err == nil {
		t.Fatal("expected an error outside a checkout")
	}
	if !strings.Contains(err.Error(), "docker-compose.yaml") {
		t.Errorf("error %q does not name the missing file", err)
	}
}

// TestWaitFor_TimesOut is the behaviour the shell script lacked: its readiness
// loops were unbounded, so a container that never came up left the terminal
// hanging with no indication of which dependency was stuck.
func TestWaitFor_TimesOut(t *testing.T) {
	start := time.Now()
	err := waitFor(context.Background(), start.Add(50*time.Millisecond), func() bool { return false })
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 5*time.Second {
		t.Error("waitFor overran its deadline substantially")
	}
}

func TestWaitFor_ReturnsWhenReady(t *testing.T) {
	calls := 0
	err := waitFor(context.Background(), time.Now().Add(5*time.Second), func() bool {
		calls++
		return calls >= 2
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWaitFor_HonoursContext keeps Ctrl-C responsive during a long wait.
func TestWaitFor_HonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitFor(ctx, time.Now().Add(time.Hour), func() bool { return false })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestDevReset_NotWriteGated pins the distinction --allow-writes draws: it
// protects deployed state, not anything destructive. dev reset only drives
// local docker, so gating it would train an operator to pass the flag out of
// habit — which is exactly what makes it useless on the commands that reach
// production.
func TestDevReset_NotWriteGated(t *testing.T) {
	if isMutating("dev reset") {
		t.Error("dev reset is listed as a deployed-state mutation; it only touches local docker")
	}
	for _, name := range []string{"customer create", "customer plan", "customer rename", "key rotate"} {
		if !isMutating(name) {
			t.Errorf("%q reaches deployed state and must stay gated", name)
		}
	}
}

func TestGitDescribe_FallsBackOutsideGit(t *testing.T) {
	if got := gitDescribe(context.Background(), t.TempDir()); got == "" {
		t.Error("gitDescribe returned an empty version")
	}
}
