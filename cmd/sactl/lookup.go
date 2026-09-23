package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/domain"
)

func lookupGroup() group {
	return group{
		name:    "lookup",
		summary: "run domain and IP intelligence lookups",
		commands: []command{
			lookupCommandFor("domain", "domains", "/v1/domain/lookup", domain.AllLookupNames, defaultDomainLookups),
			lookupCommandFor("ip", "ips", "/v1/ip/lookup", domain.AllIPLookupNames, defaultIPLookups),
		},
	}
}

// Default sets, used when --lookups is omitted. They are the fast, no-third-party
// lookups: a bare `sactl lookup domain example.com` should answer promptly
// rather than sitting on a certificate transparency query.
var (
	defaultDomainLookups = []string{
		domain.LookupWhoisName, domain.LookupDNSName, domain.LookupSSLName,
		domain.LookupHeadersName, domain.LookupEmailSecurityName,
		domain.LookupDNSSecurityName, domain.LookupRiskName,
	}
	defaultIPLookups = []string{
		domain.LookupGeoName, domain.LookupASNName,
		domain.LookupReverseDNSName, domain.LookupAbuseContactName,
	}
)

type lookupFlags struct {
	api     *apiFlags
	lookups string
}

func lookupCommandFor(name, field, path string, all, defaults []string) command {
	return command{
		name:    name,
		summary: "look up one or more " + name + "s",
		usage:   strings.ToUpper(name) + " [" + strings.ToUpper(name) + "...] [--lookups a,b,c]",
		flags: func(fs *flag.FlagSet) any {
			f := &lookupFlags{api: registerAPIFlags(fs)}
			fs.StringVar(&f.lookups, "lookups", "", fmt.Sprintf(
				"comma-separated lookups, or 'all'. Default: %s. Available: %s",
				strings.Join(defaults, ","), strings.Join(all, ", ")))
			return f
		},
		run: func(ctx context.Context, cfg any, args []string) error {
			f := cfg.(*lookupFlags)
			if len(args) == 0 {
				return fmt.Errorf("give at least one %s, e.g. sactl lookup %s example.com", name, name)
			}
			names, err := resolveLookupNames(f.lookups, all, defaults)
			if err != nil {
				return err
			}
			return runLookup(ctx, f.api, path, field, args, names)
		},
	}
}

// resolveLookupNames turns the --lookups value into a validated list.
//
// Unknown names are rejected here rather than sent: the API answers with a 400
// naming the offender, but catching it locally saves a round trip and can list
// the valid names, which the error response does not always do for typos close
// to a real name.
func resolveLookupNames(raw string, all, defaults []string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaults, nil
	}
	if strings.EqualFold(trimmed, "all") {
		return all, nil
	}

	valid := make(map[string]bool, len(all))
	for _, n := range all {
		valid[n] = true
	}

	var out []string
	var unknown []string
	for _, part := range strings.Split(trimmed, ",") {
		n := strings.ToLower(strings.TrimSpace(part))
		if n == "" {
			continue
		}
		if !valid[n] {
			unknown = append(unknown, n)
			continue
		}
		out = append(out, n)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown lookup(s) %s; available: %s",
			strings.Join(unknown, ", "), strings.Join(all, ", "))
	}
	if len(out) == 0 {
		return nil, errors.New("--lookups resolved to nothing")
	}
	return out, nil
}

// riskScoringInputs are the lookups risk actually scores over. Requesting risk
// without at least one of them produces no risk object at all — not an empty
// one, and not an error — because ComputeRiskScore returns nil when it has
// nothing to weigh. That is defensible but silent, and reads as the API being
// broken, so the CLI says so up front.
var riskScoringInputs = map[string]bool{
	domain.LookupThreatIntelName:   true,
	domain.LookupReputationName:    true,
	domain.LookupSSLName:           true,
	domain.LookupHeadersName:       true,
	domain.LookupEmailSecurityName: true,
	domain.LookupWhoisName:         true, // supplies domain_age
}

func warnIfRiskCannotScore(lookups []string) {
	wantsRisk := false
	hasInput := false
	for _, n := range lookups {
		if n == domain.LookupRiskName {
			wantsRisk = true
		}
		if riskScoringInputs[n] {
			hasInput = true
		}
	}
	if !wantsRisk || hasInput {
		return
	}
	var names []string
	for n := range riskScoringInputs {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr,
		"sactl: risk was requested but none of the lookups it scores over were (%s), so no risk will be returned\n",
		strings.Join(names, ", "))
}

func runLookup(ctx context.Context, api *apiFlags, path, field string, targets, lookups []string) error {
	warnIfRiskCannotScore(lookups)

	body := map[string]any{field: targets, "lookups": lookups}

	// Lookups fan out to third parties and can legitimately outlast the default
	// request timeout, so the deadline is widened unless the caller set one.
	if api.timeout <= defaultTimeout {
		api.timeout = 120 * time.Second
	}

	raw, err := api.postJSON(ctx, path, body)
	if err != nil {
		return err
	}

	if api.jsonOut {
		var pretty any
		if err := json.Unmarshal(raw, &pretty); err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(pretty)
	}

	return renderLookup(raw, field)
}

// renderLookup prints a results envelope.
//
// Rendering is generic rather than a switch over known lookup types: the shapes
// come straight from the API, and a hand-written renderer per lookup would need
// updating every time one is added — the CLI would then quietly omit new fields
// while appearing to work.
func renderLookup(raw []byte, field string) error {
	var envelope struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(envelope.Results) == 0 {
		fmt.Println("No results.")
		return nil
	}

	// The target key is "domain" or "ip"; trim the plural request field to it.
	targetKey := strings.TrimSuffix(field, "s")

	for i, result := range envelope.Results {
		if i > 0 {
			fmt.Println()
		}

		target, _ := result[targetKey].(string)
		fmt.Printf("── %s ", target)
		if inputs, ok := result["inputs"].([]any); ok && len(inputs) > 1 {
			fmt.Printf("(from %d inputs) ", len(inputs))
		}
		fmt.Println(strings.Repeat("─", max(0, 60-len(target))))

		// Errors first: a partial failure is the thing an operator most needs
		// to notice, and burying it under the data that did arrive hides it.
		if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
			fmt.Println("\n  errors")
			for _, e := range errs {
				if m, ok := e.(map[string]any); ok {
					fmt.Printf("    %v: %v\n", m["lookup"], m["message"])
				}
			}
		}

		for _, name := range sortedKeys(result) {
			switch name {
			case targetKey, "inputs", "errors":
				continue
			}
			section, ok := result[name].(map[string]any)
			if !ok {
				continue
			}
			cached := ""
			if hit, present := section["cache_hit"].(bool); present && hit {
				cached = "  (cached)"
			}
			fmt.Printf("\n  %s%s\n", name, cached)

			trimmed := make(map[string]any, len(section))
			for k, v := range section {
				if k == "cache_hit" {
					continue
				}
				trimmed[k] = v
			}
			printMap(trimmed, "    ")
		}
	}
	return nil
}
