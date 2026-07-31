package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The dev group holds commands that act on the local development stack and
// never on a deployed environment.
//
// It is a separate group on purpose. Every other command in this binary is
// normally pointed at production — `sactl customer list` reads Neon — so a
// destructive local command sitting alongside them invites a misfire. Grouping
// under "dev" makes the blast radius readable from the command itself.
func devGroup() group {
	return group{
		name:    "dev",
		summary: "local development stack (never touches a deployed environment)",
		commands: []command{
			devReset(),
		},
	}
}

type devResetFlags struct {
	yes     bool
	timeout time.Duration
	noPrune bool
}

func devReset() command {
	return command{
		name:    "reset",
		summary: "tear down the local stack, wipe its volumes, and rebuild",
		usage:   "[--yes] [--no-prune]",
		flags: func(fs *flag.FlagSet) any {
			f := &devResetFlags{}
			fs.BoolVar(&f.yes, "yes", false, "skip the confirmation prompt")
			fs.BoolVar(&f.noPrune, "no-prune", false, "keep the Docker build cache")
			fs.DurationVar(&f.timeout, "timeout", 5*time.Minute,
				"how long to wait for postgres and the API to become ready")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*devResetFlags)

			if err := requireWrites("wipe and rebuild the local stack"); err != nil {
				return err
			}

			root, err := repoRoot()
			if err != nil {
				return err
			}
			if _, err := exec.LookPath("docker"); err != nil {
				return errors.New("docker is not on PATH")
			}

			// The reset only ever touches local Docker volumes — it cannot
			// reach Neon or Upstash. Saying so explicitly matters because this
			// binary is usually pointed at production, and an operator who has
			// just run `customer list` against Neon needs to know this is not
			// the same target.
			fmt.Printf("This wipes the LOCAL Docker stack in %s:\n", root)
			fmt.Println("  - stops all containers")
			fmt.Println("  - deletes the postgres and redis volumes (all local data)")
			if !f.noPrune {
				fmt.Println("  - prunes the Docker build cache")
			}
			fmt.Println("  - rebuilds and restarts")
			fmt.Println("\nDeployed environments are unaffected; only local Docker is touched.")

			if !f.yes {
				if !stdinIsTerminal() {
					return errors.New("this is destructive and needs confirmation; pass --yes to proceed without a prompt")
				}
				fmt.Print("\nProceed? [y/N] ")
				var answer string
				_, _ = fmt.Scanln(&answer)
				switch strings.ToLower(strings.TrimSpace(answer)) {
				case "y", "yes":
				default:
					return errors.New("aborted")
				}
			}

			return runDevReset(ctx, root, f)
		},
	}
}

func runDevReset(ctx context.Context, root string, f *devResetFlags) error {
	// The compose file bakes VERSION into the image, matching what `make build`
	// and the deploy workflow do, so a local container reports the same version
	// string a deployed one would.
	version := gitDescribe(ctx, root)
	env := append(os.Environ(), "VERSION="+version)
	fmt.Printf("\n==> Building version %s\n", version)

	steps := []struct {
		label string
		args  []string
	}{
		{"Stopping containers", []string{"compose", "down"}},
		{"Removing postgres and redis volumes", []string{"compose", "down", "-v"}},
		{"Pruning build cache", []string{"builder", "prune", "-f"}},
		{"Rebuilding and starting", []string{"compose", "up", "--build", "-d"}},
	}

	for _, step := range steps {
		if f.noPrune && step.args[0] == "builder" {
			continue
		}
		fmt.Printf("\n==> %s\n", step.label)
		if err := streamCommand(ctx, root, env, "docker", step.args...); err != nil {
			return fmt.Errorf("%s: %w", strings.ToLower(step.label), err)
		}
	}

	// The shell script this replaces looped forever waiting for readiness. A
	// container that never becomes healthy left the terminal hanging with no
	// indication of which dependency was stuck.
	deadline := time.Now().Add(f.timeout)

	fmt.Println("\n==> Waiting for postgres")
	if err := waitFor(ctx, deadline, func() bool {
		return exec.CommandContext(ctx, "docker", "compose", "exec", "-T", "postgres",
			"pg_isready", "-U", "intelligence", "-d", "intelligence_api").Run() == nil
	}); err != nil {
		return fmt.Errorf("postgres did not become ready within %s: %w", f.timeout, err)
	}

	fmt.Println("==> Waiting for the API")
	client := &http.Client{Timeout: 2 * time.Second}
	if err := waitFor(ctx, deadline, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8080/v1/hello", nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}); err != nil {
		return fmt.Errorf("the API did not become ready within %s: %w\n"+
			"       check container logs with: docker compose logs api", f.timeout, err)
	}

	fmt.Println("\nLocal stack is up at http://localhost:8080")
	return nil
}

// waitFor polls until ready returns true, the deadline passes, or ctx ends.
func waitFor(ctx context.Context, deadline time.Time, ready func() bool) error {
	for {
		if ready() {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// streamCommand runs a command in dir, forwarding its output as it arrives.
// Docker builds take minutes, so buffering would leave the terminal looking
// hung through the slowest part.
func streamCommand(ctx context.Context, dir string, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// gitDescribe returns the version string the Makefile and deploy workflow use,
// falling back to "dev" outside a git checkout.
func gitDescribe(ctx context.Context, dir string) string {
	cmd := exec.CommandContext(ctx, "git", "describe", "--tags", "--always", "--dirty")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "dev"
	}
	if v := strings.TrimSpace(string(out)); v != "" {
		return v
	}
	return "dev"
}

// repoRoot walks up from the working directory looking for the compose file.
//
// Walking up rather than requiring the repo root means the command works from
// any subdirectory, and the error names what was missing instead of failing
// later inside docker with a message about no configuration file.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "docker-compose.yaml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no docker-compose.yaml found here or in any parent directory; " +
				"run this from the intelligence-api checkout")
		}
		dir = parent
	}
}
