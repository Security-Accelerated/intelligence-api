package main

import (
	"sort"
	"strings"
	"testing"
)

// rowOrder returns the position of each label in out, so an ordering assertion
// reads as "these appear in this order" rather than a chain of comparisons.
func rowOrder(out string, labels ...string) []int {
	positions := make([]int, len(labels))
	for i, l := range labels {
		positions[i] = strings.Index(out, l)
	}
	return positions
}

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
	if got := rowOrder(out, "200", "400", "500"); !sort.IntsAreSorted(got) {
		t.Errorf("rows are not ordered by count then name (positions %v):\n%s", got, out)
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
