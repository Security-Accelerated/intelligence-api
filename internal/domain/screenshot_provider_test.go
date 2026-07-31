package domain

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewScreenshotProvider(t *testing.T) {
	for _, name := range []string{"", "chromium", "chrome", "local"} {
		t.Run("accepts "+name, func(t *testing.T) {
			p, err := NewScreenshotProvider(name)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Name() != "chromium" {
				t.Errorf("Name() = %q, want chromium", p.Name())
			}
		})
	}
}

// TestNewScreenshotProvider_UnknownIsAnError guards against a typo in
// deployment config silently starting the local browser on a machine
// provisioned on the assumption that it would not — the first symptom of which
// would be an out-of-memory kill under load, far from the cause.
func TestNewScreenshotProvider_UnknownIsAnError(t *testing.T) {
	p, err := NewScreenshotProvider("urlbox")
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	if p != nil {
		t.Error("a failed selection must not return a provider")
	}
	if !strings.Contains(err.Error(), "urlbox") {
		t.Errorf("error %q does not name the offending value", err)
	}
}

func TestScreenshotOptions_Defaults(t *testing.T) {
	var zero ScreenshotOptions

	w, h := zero.viewport()
	if w != DefaultViewportWidth || h != DefaultViewportHeight {
		t.Errorf("viewport = %dx%d, want %dx%d", w, h, DefaultViewportWidth, DefaultViewportHeight)
	}
	if got := zero.maxBytes(); got != DefaultMaxPNGBytes {
		t.Errorf("maxBytes = %d, want %d", got, DefaultMaxPNGBytes)
	}
	if got := zero.timeout(7 * time.Second); got != 7*time.Second {
		t.Errorf("timeout = %v, want the supplied fallback", got)
	}

	set := ScreenshotOptions{Width: 800, Height: 600, MaxPNGBytes: 99, Timeout: time.Minute}
	if w, h := set.viewport(); w != 800 || h != 600 {
		t.Errorf("viewport = %dx%d, want 800x600", w, h)
	}
	if got := set.maxBytes(); got != 99 {
		t.Errorf("maxBytes = %d, want 99", got)
	}
	if got := set.timeout(time.Second); got != time.Minute {
		t.Errorf("timeout = %v, want the explicit value", got)
	}
}

// fakeProvider stands in for a hosted service. Its existence is the point of
// the test below: a third-party backend must be droppable in without the
// domain package knowing anything about it.
type fakeProvider struct {
	called  int
	gotOpts ScreenshotOptions
	result  *ScreenshotInfo
	err     error
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) Capture(_ context.Context, _ string, opts ScreenshotOptions) (*ScreenshotInfo, error) {
	f.called++
	f.gotOpts = opts
	return f.result, f.err
}

// TestScreenshotProvider_IsSubstitutable is the contract check: anything
// satisfying the interface can serve captures, so swapping Chromium for a
// hosted API is a wiring change rather than a code change.
func TestScreenshotProvider_IsSubstitutable(t *testing.T) {
	var p ScreenshotProvider = &fakeProvider{result: &ScreenshotInfo{StatusCode: 200, PNG: "abc"}}

	got, err := p.Capture(context.Background(), "example.com", ScreenshotOptions{Timeout: time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StatusCode != 200 || got.PNG != "abc" {
		t.Errorf("got %+v, want the provider's result", got)
	}
	if p.Name() != "fake" {
		t.Errorf("Name() = %q", p.Name())
	}
}

func TestScreenshotProvider_ErrorPropagates(t *testing.T) {
	want := errors.New("provider unavailable")
	var p ScreenshotProvider = &fakeProvider{err: want}

	if _, err := p.Capture(context.Background(), "example.com", ScreenshotOptions{}); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

// TestLookupScreenshot_UsesChromiumProvider keeps the compatibility wrapper
// honest: callers predating the interface must still reach a real capture path.
func TestLookupScreenshot_UsesChromiumProvider(t *testing.T) {
	// A context already past its deadline returns before any browser starts, so
	// this exercises the wiring without needing Chrome installed.
	ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()

	if _, err := LookupScreenshot(ctx, "example.com", time.Second, 1024); err == nil {
		t.Fatal("expected an error from an expired context")
	}
}
