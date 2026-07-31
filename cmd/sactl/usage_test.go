package main

import (
	"strings"
	"testing"
)

// TestRenderUsage_HitRateIsNotRescaled guards a defect this output actually
// had: cache_hit_rate arrives from the API already expressed as a percentage
// (usage/query.go multiplies by 100), and multiplying again rendered a real
// 79.2% figure as "7922.3%". A percentage above 100 is obviously wrong to a
// reader, but only if someone looks — nothing else would have caught it.
func TestRenderUsage_HitRateIsNotRescaled(t *testing.T) {
	out := captureStdout(t, func() {
		renderUsage(usageSummary{
			TotalRequests: 1519,
			CacheHits:     1590,
			CacheMisses:   417,
			CacheHitRate:  79.2, // already a percentage
		}, &usageFlags{days: 1})
	})

	if !strings.Contains(out, "79.2% hit rate") {
		t.Errorf("output does not show the hit rate verbatim:\n%s", out)
	}
	if strings.Contains(out, "7920") || strings.Contains(out, "7922") {
		t.Errorf("hit rate was rescaled:\n%s", out)
	}
}

// TestRenderUsage_ZeroRequests keeps an empty window from rendering a wall of
// zeroes and a NaN share.
func TestRenderUsage_ZeroRequests(t *testing.T) {
	out := captureStdout(t, func() {
		renderUsage(usageSummary{}, &usageFlags{days: 7})
	})
	if !strings.Contains(out, "No requests in this period") {
		t.Errorf("expected an explicit empty message, got:\n%s", out)
	}
	if strings.Contains(out, "NaN") {
		t.Errorf("output contains NaN:\n%s", out)
	}
}

func TestPrintCounts_StableOrderAndShares(t *testing.T) {
	out := captureStdout(t, func() {
		printCounts("Status codes", map[string]int{"200": 80, "400": 20, "500": 20}, 100, false)
	})

	// Highest first; equal counts break ties by name so repeated runs match.
	i200, i400, i500 := strings.Index(out, "200"), strings.Index(out, "400"), strings.Index(out, "500")
	if !(i200 < i400 && i400 < i500) {
		t.Errorf("rows are not ordered by count then name:\n%s", out)
	}
	if !strings.Contains(out, "80.0%") {
		t.Errorf("expected a share column:\n%s", out)
	}
}

// TestPrintCounts_NoTotalOmitsShares covers feature usage, whose denominator is
// lookups rather than requests — a percentage there would be meaningless.
func TestPrintCounts_NoTotalOmitsShares(t *testing.T) {
	out := captureStdout(t, func() {
		printCounts("Feature usage", map[string]int{"dns": 5, "unused": 0}, 0, true)
	})
	if strings.Contains(out, "%") {
		t.Errorf("shares shown without a meaningful denominator:\n%s", out)
	}
	if strings.Contains(out, "unused") {
		t.Errorf("zero-count features should be hidden:\n%s", out)
	}
}
