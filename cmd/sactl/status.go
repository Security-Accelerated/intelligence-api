package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// checker accumulates pass/fail results and renders them, replacing the shell
// scripts' `check` helper.
type checker struct {
	pass, fail int
}

func (c *checker) report(ok bool, desc string, detail string) {
	mark := "\033[32m✓\033[0m"
	if ok {
		c.pass++
	} else {
		mark = "\033[31m✗\033[0m"
		c.fail++
	}
	if detail != "" {
		fmt.Printf("  %s %s — %s\n", mark, desc, detail)
		return
	}
	fmt.Printf("  %s %s\n", mark, desc)
}

// err returns a non-nil error when anything failed, so the command's exit code
// reflects the result. The scripts this replaces exited 0 on a failed check in
// some paths, which made them useless in CI.
func (c *checker) err() error {
	fmt.Printf("\nResults: %d passed, %d failed\n", c.pass, c.fail)
	if c.fail > 0 {
		return fmt.Errorf("%d check(s) failed", c.fail)
	}
	return nil
}

type healthResponse struct {
	Status     string            `json:"status"`
	Components map[string]string `json:"components"`
}

func statusCommand() command {
	return command{
		name:    "status",
		summary: "check deployment health: endpoints, dependencies and version",
		flags: func(fs *flag.FlagSet) any {
			return registerAPIFlags(fs)
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			return runStatus(ctx, cfg.(*apiFlags))
		},
	}
}

// getJSONUnauthenticated fetches an endpoint that needs no API key.
func (f *apiFlags) getJSONUnauthenticated(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trimHost(f.host)+path, nil)
	if err != nil {
		return err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// /v1/health answers 503 when a dependency is down, and the body is the
	// interesting part in exactly that case, so the status is not treated as a
	// transport failure.
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode %s (HTTP %d): %w", path, resp.StatusCode, err)
	}
	return nil
}

func trimHost(h string) string {
	for len(h) > 0 && h[len(h)-1] == '/' {
		h = h[:len(h)-1]
	}
	return h
}

// infoResponse mirrors the parts of /v1/info the CLI renders. It is decoded
// loosely rather than into config.StatusSnapshot: /v1/info merges live runtime
// data into the static snapshot at request time, so the wire shape is a
// superset of any single struct in the config package.
type infoResponse struct {
	System struct {
		Name      string    `json:"name"`
		Version   string    `json:"version"`
		Mode      string    `json:"mode"`
		SessionID string    `json:"session_id"`
		StartTime time.Time `json:"start_time"`
		Uptime    string    `json:"uptime"`
		Host      string    `json:"host"`
		OS        string    `json:"os"`
		Kernel    string    `json:"kernel"`
		Arch      string    `json:"architecture"`
		GoVersion string    `json:"golang_version"`
	} `json:"system"`
	Runtime struct {
		Goroutines  int     `json:"goroutines"`
		HeapAllocMB float64 `json:"heap_alloc_mb"`
	} `json:"runtime"`
	Database map[string]any `json:"database"`
	Cache    map[string]any `json:"cache"`
	Lookups  map[string]any `json:"lookups"`
	Services map[string]any `json:"services"`
}

func infoCommand() command {
	return command{
		name:    "info",
		summary: "show the running service's configuration and runtime state",
		flags: func(fs *flag.FlagSet) any {
			f := registerAPIFlags(fs)
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			return runInfo(ctx, cfg.(*apiFlags))
		},
	}
}

// runInfo fetches and renders /v1/info, shared by the command and the menu.
func runInfo(ctx context.Context, f *apiFlags) error {
	var info infoResponse
	if err := f.getJSON(ctx, "/v1/info", &info); err != nil {
		return err
	}

	if f.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	fmt.Printf("%s %s (%s)\n", info.System.Name, info.System.Version, info.System.Mode)
	fmt.Printf("  host      %s  %s/%s\n", info.System.Host, info.System.OS, info.System.Arch)
	fmt.Printf("  runtime   %s, %d goroutines, %.1f MB heap\n",
		info.System.GoVersion, info.Runtime.Goroutines, info.Runtime.HeapAllocMB)
	fmt.Printf("  uptime    %s (since %s)\n", info.System.Uptime, info.System.StartTime.Format(time.RFC3339))
	fmt.Printf("  session   %s\n", info.System.SessionID)

	for _, section := range []struct {
		title string
		data  map[string]any
	}{
		{"Database", info.Database},
		{"Cache", info.Cache},
		{"Lookups", info.Lookups},
		{"Services", info.Services},
	} {
		if len(section.data) == 0 {
			continue
		}
		fmt.Printf("\n%s\n", section.title)
		printMap(section.data, "  ")
	}
	return nil
}

// printMap renders a decoded JSON object as indented key/value lines, recursing
// into nested objects. /v1/info's shape is assembled from several structs and
// grows as config does; rendering it generically means a new field appears here
// without the CLI needing to know about it.
func printMap(m map[string]any, indent string) {
	tw := newTabWriter()
	for _, k := range sortedKeys(m) {
		switch v := m[k].(type) {
		case map[string]any:
			_ = tw.Flush()
			fmt.Printf("%s%s:\n", indent, k)
			printMap(v, indent+"  ")
		case []any:
			fmt.Fprintf(tw, "%s%s\t%s\n", indent, k, formatSlice(v))
		case nil:
			fmt.Fprintf(tw, "%s%s\t-\n", indent, k)
		default:
			fmt.Fprintf(tw, "%s%s\t%v\n", indent, k, v)
		}
	}
	_ = tw.Flush()
}

func formatSlice(v []any) string {
	parts := make([]string, 0, len(v))
	for _, item := range v {
		parts = append(parts, fmt.Sprint(item))
	}
	return truncate(joinComma(parts), 100)
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// runStatus performs the deployment checks. It is separate from the command so
// the interactive menu runs exactly the same code as the flag interface.
func runStatus(ctx context.Context, f *apiFlags) error {
	c := &checker{}

	fmt.Printf("=== %s ===\n", f.host)

	// Reachability, unauthenticated.
	if code, err := f.probe(ctx, http.MethodGet, "/v1/hello"); err != nil {
		c.report(false, "app responding", err.Error())
	} else {
		c.report(code == http.StatusOK, "app responding", fmt.Sprintf("GET /v1/hello -> %d", code))
	}

	// The auth middleware being in the chain at all is worth asserting:
	// a misconfigured deployment that serves lookups unauthenticated
	// would otherwise look perfectly healthy.
	if code, err := f.probe(ctx, http.MethodPost, "/v1/domain/lookup"); err != nil {
		c.report(false, "auth middleware active", err.Error())
	} else {
		c.report(code == http.StatusUnauthorized, "auth middleware active",
			fmt.Sprintf("POST /v1/domain/lookup without a key -> %d, want 401", code))
	}

	// Dependencies, via the service's own view of them.
	var health healthResponse
	healthErr := f.getJSONUnauthenticated(ctx, "/v1/health", &health)
	if healthErr != nil {
		c.report(false, "dependency health", healthErr.Error())
	} else {
		c.report(health.Status == "ok", "dependency health", "status="+health.Status)
		fmt.Println()
		tw := newTabWriter()
		for _, name := range sortedKeys(health.Components) {
			fmt.Fprintf(tw, "  %s\t%s\n", name, health.Components[name])
		}
		_ = tw.Flush()
	}

	// Version, which needs the admin key. Absent one, skip rather than
	// fail: the health checks above are the point of this command.
	if _, err := f.adminKey(); err == nil {
		var info infoResponse
		if err := f.getJSON(ctx, "/v1/info", &info); err != nil {
			c.report(false, "admin endpoint reachable", err.Error())
		} else {
			c.report(true, "admin endpoint reachable", "")
			fmt.Printf("\n  version %s, up %s, started %s\n",
				info.System.Version, info.System.Uptime,
				info.System.StartTime.Format(time.RFC3339))
		}
	} else {
		fmt.Println("\n  (no admin key: skipping version and configuration)")
	}

	fmt.Println()
	return c.err()
}
