// Command sactl is the operator CLI for the Intelligence API.
//
// It exists to keep routine administration off raw psql. Creating a customer,
// minting a key or changing a plan by hand means writing the same multi-table
// INSERT every time and remembering that keys are stored as a sha256 digest —
// a step that fails silently, producing a row that simply never authenticates.
// Going through the same packages the server uses means the CLI cannot disagree
// with it about key format, hashing, plan names or rotation semantics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

var version = "dev"

// defaultEnvFile is read by every invocation unless --env-file says otherwise.
const defaultEnvFile = ".env"

// defaultTimeout bounds a single API request.
const defaultTimeout = 15 * time.Second

// stdinIsTerminal reports whether stdin is an interactive terminal.
func stdinIsTerminal() bool {
	stat, err := os.Stdin.Stat()
	return err == nil && (stat.Mode()&os.ModeCharDevice) != 0
}

// nowFunc returns the current time. It is a variable so tests can pin it.
var nowFunc = time.Now

// command is one leaf subcommand. flags registers the command's own flags on a
// FlagSet the dispatcher owns, so -h works uniformly without each command
// re-implementing it.
type command struct {
	name    string
	summary string
	// usage is appended to the generated usage line, e.g. "--name X --plan pro".
	usage string
	flags func(*flag.FlagSet) any
	run   func(ctx context.Context, cfg any, args []string) error
}

// group is a namespace of related commands, e.g. "customer".
type group struct {
	name     string
	summary  string
	commands []command
}

func groups() []group {
	return []group{
		customerGroup(),
		keyGroup(),
	}
}

// topLevel are commands with no group, e.g. "sactl status".
func topLevel() []command {
	return []command{
		statusCommand(),
		infoCommand(),
		usageCommand(),
		smokeCommand(),
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		// flag.ErrHelp means the user asked for usage; that is not a failure,
		// and printing "error: flag: help requested" over the help they asked
		// for would be noise.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "sactl: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		// Interactive only when a person is actually there to answer. Piped or
		// redirected input would otherwise hit EOF on the first prompt and quit
		// immediately, which reads as the tool being broken; printing usage is
		// the more useful answer for `sactl | less` or a CI invocation.
		if !stdinIsTerminal() {
			usage(os.Stdout)
			return nil
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if _, err := loadEnvFile(defaultEnvFile); err != nil {
			return fmt.Errorf("read %s: %w", defaultEnvFile, err)
		}
		sh := newShell(os.Stdin, os.Stdout)
		defer sh.close()
		return sh.runShell(ctx)
	}

	switch args[0] {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return nil
	case "-v", "--version", "version":
		fmt.Println("sactl", version)
		return nil
	}

	// Signals cancel in-flight work. Every command takes a context, so a
	// long-running query is interrupted rather than orphaned.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, c := range topLevel() {
		if c.name == args[0] {
			return dispatch(ctx, "sactl "+c.name, c, args[1:])
		}
	}

	for _, g := range groups() {
		if g.name != args[0] {
			continue
		}
		if len(args) < 2 {
			groupUsage(os.Stderr, g)
			return fmt.Errorf("%s needs a subcommand", g.name)
		}
		for _, c := range g.commands {
			if c.name == args[1] {
				return dispatch(ctx, "sactl "+g.name+" "+c.name, c, args[2:])
			}
		}
		groupUsage(os.Stderr, g)
		return fmt.Errorf("unknown subcommand %q for %s", args[1], g.name)
	}

	usage(os.Stderr)
	return fmt.Errorf("unknown command %q", args[0])
}

func dispatch(ctx context.Context, name string, c command, args []string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s %s\n\n%s\n\n", name, c.usage, c.summary)
		fs.PrintDefaults()
	}

	// Every command gets --env-file. Credentials live in a file the shell
	// cannot safely source (see loadEnvFile), so resolving it here means one
	// implementation rather than one per command.
	var envFile string
	fs.StringVar(&envFile, "env-file", defaultEnvFile,
		"file of KEY=VALUE pairs to load into the environment; a missing file is not an error")

	var cfg any
	if c.flags != nil {
		cfg = c.flags(fs)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	loaded, err := loadEnvFile(envFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", envFile, err)
	}
	if loaded > 0 {
		// Announced on stderr, not stdout: --json output must stay parseable,
		// but an operator should still see where credentials came from.
		fmt.Fprintf(os.Stderr, "sactl: loaded %d variable(s) from %s\n", loaded, envFile)
	}

	return c.run(ctx, cfg, fs.Args())
}

func usage(w *os.File) {
	fmt.Fprintf(w, "sactl %s — operator CLI for the Intelligence API\n\nUsage: sactl <command> [flags]\n\n", version)

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "Commands:")
	for _, c := range topLevel() {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
	}
	for _, g := range groups() {
		fmt.Fprintf(tw, "  %s <subcommand>\t%s\n", g.name, g.summary)
	}
	fmt.Fprintln(tw)
	for _, g := range groups() {
		fmt.Fprintf(tw, "%s subcommands:\n", g.name)
		for _, c := range g.commands {
			fmt.Fprintf(tw, "  %s %s\t%s\n", g.name, c.name, c.summary)
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()

	fmt.Fprint(w, `Configuration comes from the same sources as the server: config files and
environment variables (POSTGRES_URL, POSTGRES_HOST, SMOKE_ADMIN_KEY, ...).

Every command reads ./.env first, so credentials kept there work with no extra
setup. Point elsewhere with --env-file, or disable it with --env-file=/dev/null.
Variables already exported always win over the file. Do not source the file
yourself: connection strings contain '&', which the shell would treat as a
background operator and truncate the value at.

    sactl customer list --database-url "$NEON_CONNECTION_STRING"
    sactl status --host http://localhost:8080

Run 'sactl <command> -h' for a command's flags.
`)
}

func groupUsage(w *os.File, g group) {
	fmt.Fprintf(w, "Usage: sactl %s <subcommand> [flags]\n\n", g.name)
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, c := range g.commands {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
}

// newTabWriter returns the writer every command uses for tabular output, so
// column behaviour is identical across the CLI.
func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

// sortedKeys returns m's keys in sorted order, for stable output.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// truncate shortens s to at most n runes, marking any elision.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// yesNo renders a boolean for table output.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// dash returns s, or "-" when empty, so a blank cell is visibly intentional.
func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
