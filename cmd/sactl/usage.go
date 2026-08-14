package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

type usageSummary struct {
	TotalRequests  int            `json:"total_requests"`
	CacheHits      int            `json:"cache_hits"`
	CacheMisses    int            `json:"cache_misses"`
	CacheHitRate   float64        `json:"cache_hit_rate"`
	AvgLatencyMs   float64        `json:"avg_latency_ms"`
	TotalDomains   int            `json:"total_domains"`
	TotalIPs       int            `json:"total_ips"`
	StatusCodes    map[string]int `json:"status_codes"`
	FeatureUsage   map[string]int `json:"feature_usage"`
	RequestsByPath map[string]int `json:"requests_by_path"`
	PeriodStart    time.Time      `json:"period_start"`
	PeriodEnd      time.Time      `json:"period_end"`
}

type usageFlags struct {
	api      *apiFlags
	days     int
	customer int
	apiKey   int
}

func usageCommand() command {
	return command{
		name:    "usage",
		summary: "query request analytics from the admin endpoint",
		usage:   "[--days N] [--customer N] [--api-key N]",
		flags: func(fs *flag.FlagSet) any {
			f := &usageFlags{api: registerAPIFlags(fs)}
			fs.IntVar(&f.days, "days", 30, "lookback window in days (1-365)")
			fs.IntVar(&f.customer, "customer", 0, "restrict to one customer ID")
			fs.IntVar(&f.apiKey, "api-key", 0, "restrict to one API key ID")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			return runUsage(ctx, cfg.(*usageFlags))
		},
	}
}

// runUsage queries and renders the analytics, shared by the command and the menu.
func runUsage(ctx context.Context, f *usageFlags) error {
	// The endpoint enforces this too, but rejecting here turns a 400 into a
	// message that names the flag the operator actually typed.
	if f.days < 1 || f.days > 365 {
		return fmt.Errorf("days must be between 1 and 365, got %d", f.days)
	}
	// Negative IDs were previously ignored by the `> 0` guards below, so a
	// typo produced unfiltered totals for every customer while appearing to
	// answer a question about one.
	if f.customer < 0 {
		return fmt.Errorf("customer must be a positive ID, got %d", f.customer)
	}
	if f.apiKey < 0 {
		return fmt.Errorf("api-key must be a positive ID, got %d", f.apiKey)
	}

	query := "/v1/admin/usage?days=" + strconv.Itoa(f.days)
	if f.customer > 0 {
		query += "&customer_id=" + strconv.Itoa(f.customer)
	}
	if f.apiKey > 0 {
		query += "&api_key_id=" + strconv.Itoa(f.apiKey)
	}

	var s usageSummary
	if err := f.api.getJSON(ctx, query, &s); err != nil {
		return err
	}

	if f.api.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}

	renderUsage(s, f)
	return nil
}

func renderUsage(s usageSummary, f *usageFlags) {
	scope := "all customers"
	if f.customer > 0 {
		scope = fmt.Sprintf("customer %d", f.customer)
	}
	if f.apiKey > 0 {
		scope += fmt.Sprintf(", API key %d", f.apiKey)
	}

	fmt.Printf("Usage — %s, last %d days\n", scope, f.days)
	if !s.PeriodStart.IsZero() {
		fmt.Printf("  %s to %s\n", s.PeriodStart.Format(time.DateOnly), s.PeriodEnd.Format(time.DateOnly))
	}

	if s.TotalRequests == 0 {
		fmt.Println("\nNo requests in this period.")
		return
	}

	fmt.Printf("\n  requests   %d\n", s.TotalRequests)
	fmt.Printf("  domains    %d\n", s.TotalDomains)
	fmt.Printf("  IPs        %d\n", s.TotalIPs)
	fmt.Printf("  latency    %.1f ms average\n", s.AvgLatencyMs)
	// cache_hit_rate already arrives as a percentage (see usage/query.go), not
	// a fraction — scaling it again here produced "7922.3%".
	//
	// Hits and misses count individual lookups, not requests, so they do not
	// sum to TotalRequests. Labeling them makes that visible rather than
	// looking like an arithmetic error.
	fmt.Printf("  cache      %.1f%% hit rate (%d hits, %d misses, counted per lookup)\n",
		s.CacheHitRate, s.CacheHits, s.CacheMisses)

	printCounts("Status codes", s.StatusCodes, s.TotalRequests, false)
	printCounts("Requests by path", s.RequestsByPath, s.TotalRequests, false)
	// feature_usage counts lookups requested regardless of how they were
	// served, so a cache hit does not make a feature look less used. Its
	// denominator is not the request count, so no percentage is shown.
	printCounts("Feature usage (lookups requested)", s.FeatureUsage, 0, true)
}

// printCounts renders a count map, highest first. When total is non-zero each
// row also shows its share.
func printCounts(title string, counts map[string]int, total int, hideZero bool) {
	if len(counts) == 0 {
		return
	}

	type row struct {
		name string
		n    int
	}
	rows := make([]row, 0, len(counts))
	for name, n := range counts {
		if hideZero && n == 0 {
			continue
		}
		rows = append(rows, row{name, n})
	}
	if len(rows) == 0 {
		return
	}
	// Descending by count, then by name so equal counts stay in a stable order
	// between runs rather than shuffling with Go's map iteration.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].name < rows[j].name
	})

	fmt.Printf("\n%s\n", title)
	tw := newTabWriter()
	for _, r := range rows {
		if total > 0 {
			fmt.Fprintf(tw, "  %s\t%d\t%.1f%%\n", r.name, r.n, float64(r.n)/float64(total)*100)
			continue
		}
		fmt.Fprintf(tw, "  %s\t%d\n", r.name, r.n)
	}
	_ = tw.Flush()
}
