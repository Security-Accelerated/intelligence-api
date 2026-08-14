package domain

import (
	"context"
	"fmt"
	"time"
)

// ScreenshotProvider captures a rendered image of a site.
//
// Screenshots are the one lookup that needs a browser, which makes them the
// outlier in every dimension that matters: memory, latency, and attack surface
// (the safenet proxy exists almost entirely for them). Running Chromium in the
// API process caps concurrency at roughly one browser per 500MB of machine, so
// bulk capture — the typosquat-triage case — is not reachable by buying a
// larger instance. Moving capture behind an interface means a hosted provider
// can replace the local browser without the service, the cache, the plan gating
// or the response shape knowing anything changed.
//
// Follows the ThreatIntelProvider pattern: Name for logs and diagnostics,
// a single method for the work, and construction chosen in app bootstrap.
type ScreenshotProvider interface {
	// Name identifies the provider in logs and /v1/info.
	Name() string
	// Capture renders target and returns the image. A non-200 origin is not an
	// error: the status is reported with no image, which is how a parked or
	// dead domain is distinguished from a capture failure.
	Capture(ctx context.Context, target string, opts ScreenshotOptions) (*ScreenshotInfo, error)
}

// ScreenshotOptions are the per-request knobs a provider must honor.
type ScreenshotOptions struct {
	// Timeout bounds the whole operation, probe included.
	Timeout time.Duration
	// MaxPNGBytes rejects an image larger than this rather than returning it.
	MaxPNGBytes int
	// Width and Height are the viewport. Zero means the provider's default.
	Width, Height int
}

func (o ScreenshotOptions) viewport() (int, int) {
	if o.Width <= 0 || o.Height <= 0 {
		return DefaultViewportWidth, DefaultViewportHeight
	}
	return o.Width, o.Height
}

func (o ScreenshotOptions) maxBytes() int {
	if o.MaxPNGBytes <= 0 {
		return DefaultMaxPNGBytes
	}
	return o.MaxPNGBytes
}

func (o ScreenshotOptions) timeout(fallback time.Duration) time.Duration {
	if o.Timeout <= 0 {
		return fallback
	}
	return o.Timeout
}

// Default viewport for captures.
const (
	DefaultViewportWidth  = 1280
	DefaultViewportHeight = 720
)

// DefaultScreenshotTimeout applies when a caller supplies none.
const DefaultScreenshotTimeout = 45 * time.Second

// NewScreenshotProvider returns the provider named by cfgName.
//
// Unknown names are an error rather than a silent fallback to Chromium: a typo
// in deployment config would otherwise start the local browser on a machine
// provisioned on the assumption that it would not, and the first symptom would
// be an out-of-memory kill under load.
func NewScreenshotProvider(cfgName string) (ScreenshotProvider, error) {
	switch cfgName {
	case "", "chromium", "chrome", "local":
		return NewChromiumProvider(), nil
	default:
		return nil, fmt.Errorf("unknown screenshot provider %q; supported: chromium", cfgName)
	}
}
