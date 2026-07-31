package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/security-accelerated/intelligence-api/internal/adminops"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/billing"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/database"
	"github.com/security-accelerated/intelligence-api/internal/domain"
)

// errQuit unwinds the menu stack when the operator asks to leave.
var errQuit = errors.New("quit")

// shell is the interactive front end. It calls the same run* functions the
// flag interface does, so the two cannot drift in behaviour — only in how the
// arguments are gathered.
type shell struct {
	in  *bufio.Reader
	out io.Writer

	db  *dbFlags
	api *apiFlags

	// conn is opened on first use and reused for the session. Connecting
	// eagerly would make the menu unusable whenever the database is
	// unreachable, including for the API-only actions that do not need it.
	conn  *sql.DB
	store *adminops.Store
}

func newShell(in io.Reader, out io.Writer) *shell {
	return &shell{
		in:  bufio.NewReader(in),
		out: out,
		// The interactive flow confirms in its own prompts, so the flag-level
		// confirmation is disabled to avoid asking twice.
		db:  &dbFlags{yes: true},
		api: &apiFlags{host: defaultHost, timeout: defaultTimeout},
	}
}

func (s *shell) close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// stores returns the admin store, connecting on first use.
func (s *shell) stores(ctx context.Context) (*adminops.Store, error) {
	if s.store != nil {
		return s.store, nil
	}
	db, _, err := s.db.openDB(ctx)
	if err != nil {
		return nil, err
	}
	s.conn = db
	s.store = adminops.NewStore(db)
	return s.store, nil
}

// --- prompting ---

func (s *shell) printf(format string, args ...any) {
	fmt.Fprintf(s.out, format, args...)
}

// ask reads one line. io.EOF (Ctrl-D) is reported as errQuit so every prompt
// exits cleanly rather than spinning on an endless stream of empty reads.
func (s *shell) ask(label string) (string, error) {
	s.printf("%s", label)
	line, err := s.in.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			s.printf("\n")
			return "", errQuit
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// askDefault prompts with a fallback used when the answer is blank.
func (s *shell) askDefault(label, fallback string) (string, error) {
	prompt := label
	if fallback != "" {
		prompt = fmt.Sprintf("%s (%s)", label, fallback)
	}
	answer, err := s.ask(prompt + ": ")
	if err != nil {
		return "", err
	}
	if answer == "" {
		return fallback, nil
	}
	return answer, nil
}

// askRequired re-prompts until a non-empty answer is given.
func (s *shell) askRequired(label string) (string, error) {
	for {
		answer, err := s.ask(label + ": ")
		if err != nil {
			return "", err
		}
		if answer != "" {
			return answer, nil
		}
		s.printf("  %s is required.\n", label)
	}
}

// askInt re-prompts until the answer parses as a positive integer.
func (s *shell) askInt(label string) (int, error) {
	for {
		answer, err := s.ask(label + ": ")
		if err != nil {
			return 0, err
		}
		n, convErr := strconv.Atoi(answer)
		if convErr == nil && n > 0 {
			return n, nil
		}
		s.printf("  Enter a positive whole number.\n")
	}
}

// askChoice re-prompts until the answer is one of options.
func (s *shell) askChoice(label string, options []string, fallback string) (string, error) {
	for {
		answer, err := s.askDefault(fmt.Sprintf("%s [%s]", label, strings.Join(options, "/")), fallback)
		if err != nil {
			return "", err
		}
		for _, o := range options {
			if strings.EqualFold(answer, o) {
				return o, nil
			}
		}
		s.printf("  Choose one of: %s\n", strings.Join(options, ", "))
	}
}

// askYesNo defaults to no. Every destructive prompt routes through here, so the
// safe answer is the one you get by pressing enter.
func (s *shell) askYesNo(question string) (bool, error) {
	answer, err := s.ask(question + " [y/N] ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(answer) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// --- menus ---

type menuItem struct {
	key   string
	label string
	run   func(ctx context.Context) error
}

// menu renders items and dispatches until the operator goes back or quits.
// Action errors are printed and the menu redrawn: a mistyped ID or an
// unreachable database should not end the session.
func (s *shell) menu(ctx context.Context, title string, items []menuItem, backLabel string) error {
	for {
		s.printf("\n  %s\n", title)
		for _, item := range items {
			s.printf("  %s) %s\n", item.key, item.label)
		}
		s.printf("  %s\n", backLabel)

		choice, err := s.ask("\n> ")
		if err != nil {
			return err
		}

		switch strings.ToLower(choice) {
		case "q", "quit", "exit":
			return errQuit
		case "b", "back", "":
			if strings.HasPrefix(backLabel, "b)") {
				return nil
			}
			continue
		}

		matched := false
		for _, item := range items {
			if item.key != choice {
				continue
			}
			matched = true
			if err := item.run(ctx); err != nil {
				if errors.Is(err, errQuit) {
					return err
				}
				s.printf("\n  error: %v\n", err)
			}
		}
		if !matched {
			s.printf("  Unknown option %q.\n", choice)
		}
	}
}

// runShell is the interactive entry point.
func (s *shell) runShell(ctx context.Context) error {
	s.printf("\n  Intelligence API — admin (%s)\n", version)
	s.printf("  db:  %s\n", database.Describe(s.db.viperFor()))
	s.printf("  api: %s\n", s.api.host)

	if !allowWrites {
		s.printf("  read-only — start with %s to enable changes\n", writeFlagName)
	}

	err := s.menu(ctx, "Main menu", []menuItem{
		{"1", "Run a lookup", s.lookupMenu},
		{"2", "Customers", s.customersMenu},
		{"3", "API keys", s.keysMenu},
		{"4", "Deployment status", func(ctx context.Context) error { return runStatus(ctx, s.api) }},
		{"5", "Service info", func(ctx context.Context) error { return runInfo(ctx, s.api) }},
		{"6", "Usage analytics", s.usageAction},
		{"7", "Run smoke test", s.smokeAction},
		{"8", "Settings (host, database)", s.settingsMenu},
	}, "q) Quit")

	if errors.Is(err, errQuit) {
		s.printf("\n  Bye.\n")
		return nil
	}
	return err
}

// lookupMenu runs intelligence lookups through the API, exactly as the
// commands do — the CLI never performs a lookup itself, so what it shows is
// what a customer would receive.
func (s *shell) lookupMenu(ctx context.Context) error {
	return s.menu(ctx, "Lookups", []menuItem{
		{"1", "Domain", func(ctx context.Context) error {
			return s.lookupAction(ctx, "domain", "domains", "/v1/domain/lookup",
				domain.AllLookupNames, defaultDomainLookups)
		}},
		{"2", "IP address", func(ctx context.Context) error {
			return s.lookupAction(ctx, "IP", "ips", "/v1/ip/lookup",
				domain.AllIPLookupNames, defaultIPLookups)
		}},
	}, "b) Back")
}

func (s *shell) lookupAction(ctx context.Context, label, field, path string, all, defaults []string) error {
	raw, err := s.askRequired(fmt.Sprintf("  %s(s), comma-separated", label))
	if err != nil {
		return err
	}
	var targets []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no %s given", label)
	}

	s.printf("  available: %s\n", strings.Join(all, ", "))
	choice, err := s.askDefault("  lookups (comma-separated, or 'all')", strings.Join(defaults, ","))
	if err != nil {
		return err
	}
	names, err := resolveLookupNames(choice, all, defaults)
	if err != nil {
		return err
	}

	s.printf("\n  running %d lookup(s) against %s...\n\n", len(names), s.api.host)
	return runLookup(ctx, s.api, path, field, targets, names)
}

func (s *shell) customersMenu(ctx context.Context) error {
	return s.menu(ctx, "Customers", []menuItem{
		{"1", "List", s.customerListAction},
		{"2", "Create", s.customerCreateAction},
		{"3", "Change plan", s.customerPlanAction},
		{"4", "Activate / deactivate", s.customerActiveAction},
	}, "b) Back")
}

func (s *shell) keysMenu(ctx context.Context) error {
	return s.menu(ctx, "API keys", []menuItem{
		{"1", "List a customer's keys", s.keyListAction},
		{"2", "Rotate a customer's key", s.keyRotateAction},
	}, "b) Back")
}

// --- customer actions ---

func (s *shell) customerListAction(ctx context.Context) error {
	store, err := s.stores(ctx)
	if err != nil {
		return err
	}
	customers, err := store.ListCustomers(ctx)
	if err != nil {
		return err
	}
	printCustomers(customers)
	return nil
}

func (s *shell) customerCreateAction(ctx context.Context) error {
	if err := requireWrites("create a customer"); err != nil {
		return err
	}
	name, err := s.askRequired("  Name")
	if err != nil {
		return err
	}
	plan, err := s.askChoice("  Plan", auth.Plans, auth.PlanFree)
	if err != nil {
		return err
	}
	email, err := s.ask("  Email (optional): ")
	if err != nil {
		return err
	}

	store, err := s.stores(ctx)
	if err != nil {
		return err
	}

	ok, err := s.askYesNo(fmt.Sprintf("\n  Create %q on the %s plan, in %s?",
		name, plan, database.Describe(s.db.viperFor())))
	if err != nil {
		return err
	}
	if !ok {
		s.printf("  Cancelled.\n")
		return nil
	}

	id, rawKey, err := store.CreateCustomer(ctx, name, email, plan)
	if err != nil {
		return err
	}

	s.printf("\n  Created customer %d (%s) on the %s plan.\n\n", id, name, plan)
	s.printf("    API key: %s\n\n", rawKey)
	s.printf("  Shown once and not recoverable — only its hash is stored.\n")
	return nil
}

func (s *shell) customerPlanAction(ctx context.Context) error {
	if err := requireWrites("change a customer's plan"); err != nil {
		return err
	}
	store, err := s.stores(ctx)
	if err != nil {
		return err
	}
	// Listing first means the operator picks from what exists rather than
	// recalling an ID, which is where mistyped-ID mistakes come from.
	customers, err := store.ListCustomers(ctx)
	if err != nil {
		return err
	}
	printCustomers(customers)

	id, err := s.askInt("  Customer ID")
	if err != nil {
		return err
	}
	plan, err := s.askChoice("  New plan", auth.Plans, "")
	if err != nil {
		return err
	}

	ok, err := s.askYesNo(fmt.Sprintf("  Move customer %d to %s?", id, plan))
	if err != nil || !ok {
		s.printf("  Cancelled.\n")
		return err
	}

	if err := store.SetPlan(ctx, id, plan); err != nil {
		if errors.Is(err, adminops.ErrNotFound) {
			return fmt.Errorf("no customer with ID %d", id)
		}
		return err
	}
	s.printf("  Customer %d is now on the %s plan.\n  %s\n", id, plan, planCacheNote)
	return nil
}

func (s *shell) customerActiveAction(ctx context.Context) error {
	if err := requireWrites("activate or deactivate a customer"); err != nil {
		return err
	}
	store, err := s.stores(ctx)
	if err != nil {
		return err
	}
	customers, err := store.ListCustomers(ctx)
	if err != nil {
		return err
	}
	printCustomers(customers)

	id, err := s.askInt("  Customer ID")
	if err != nil {
		return err
	}
	state, err := s.askChoice("  Set to", []string{"active", "inactive"}, "")
	if err != nil {
		return err
	}
	active := state == "active"

	ok, err := s.askYesNo(fmt.Sprintf("  Set customer %d to %s?", id, state))
	if err != nil || !ok {
		s.printf("  Cancelled.\n")
		return err
	}

	if err := store.SetActive(ctx, id, active); err != nil {
		if errors.Is(err, adminops.ErrNotFound) {
			return fmt.Errorf("no customer with ID %d", id)
		}
		return err
	}
	s.printf("  Customer %d is now %s.\n  %s\n", id, state, planCacheNote)
	return nil
}

// --- key actions ---

func (s *shell) keyListAction(ctx context.Context) error {
	store, err := s.stores(ctx)
	if err != nil {
		return err
	}
	id, err := s.askInt("  Customer ID")
	if err != nil {
		return err
	}
	keys, err := store.ListKeys(ctx, id)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		s.printf("  Customer %d has no keys.\n", id)
		return nil
	}
	printKeys(keys)
	return nil
}

func (s *shell) keyRotateAction(ctx context.Context) error {
	if err := requireWrites("rotate a key"); err != nil {
		return err
	}
	if _, err := s.stores(ctx); err != nil {
		return err
	}
	id, err := s.askInt("  Customer ID")
	if err != nil {
		return err
	}

	grace := config.Config().GetDuration("auth.rotation_grace")
	ok, err := s.askYesNo(fmt.Sprintf(
		"  Rotate customer %d's key? Existing keys stop working after %s.", id, grace))
	if err != nil || !ok {
		s.printf("  Cancelled.\n")
		return err
	}

	svc := billing.NewKeyRotationService(billing.NewRepository(s.conn), grace, noopCacheInvalidator{})
	rawKey, oldExpiry, err := svc.Rotate(ctx, id)
	if err != nil {
		return err
	}

	s.printf("\n  Rotated the key for customer %d.\n\n", id)
	s.printf("    API key: %s\n\n", rawKey)
	s.printf("  Shown once and not recoverable — only its hash is stored.\n")
	s.printf("  Previous keys stop working at %s.\n", oldExpiry.Format("2006-01-02 15:04:05 MST"))
	return nil
}

// --- API actions ---

func (s *shell) usageAction(ctx context.Context) error {
	daysStr, err := s.askDefault("  Days of history", "30")
	if err != nil {
		return err
	}
	days, convErr := strconv.Atoi(daysStr)
	if convErr != nil {
		return fmt.Errorf("%q is not a number", daysStr)
	}

	customerStr, err := s.askDefault("  Customer ID (blank for all)", "")
	if err != nil {
		return err
	}
	customer := 0
	if customerStr != "" {
		if customer, convErr = strconv.Atoi(customerStr); convErr != nil {
			return fmt.Errorf("%q is not a number", customerStr)
		}
	}

	return runUsage(ctx, &usageFlags{api: s.api, days: days, customer: customer})
}

func (s *shell) smokeAction(ctx context.Context) error {
	// The suite makes well over a hundred requests against whatever --host
	// points at, which is production by default. Worth one confirmation.
	ok, err := s.askYesNo(fmt.Sprintf("  Run the full smoke suite against %s?", s.api.host))
	if err != nil || !ok {
		s.printf("  Cancelled.\n")
		return err
	}
	return runSmoke(ctx, &smokeFlags{api: s.api})
}

func (s *shell) settingsMenu(ctx context.Context) error {
	return s.menu(ctx, "Settings", []menuItem{
		{"1", "API host", func(context.Context) error {
			host, err := s.askDefault("  API host", s.api.host)
			if err != nil {
				return err
			}
			s.api.host = host
			s.printf("  API host is now %s\n", host)
			return nil
		}},
		{"2", "Database connection string", func(context.Context) error {
			url, err := s.ask("  Connection string (blank to keep current): ")
			if err != nil {
				return err
			}
			if url == "" {
				s.printf("  Unchanged: %s\n", database.Describe(s.db.viperFor()))
				return nil
			}
			// Drop any open connection so the next action reconnects to the
			// new target rather than silently reusing the old one.
			s.close()
			s.conn, s.store = nil, nil
			s.db.databaseURL = url
			s.printf("  Database is now %s\n", database.Describe(s.db.viperFor()))
			return nil
		}},
	}, "b) Back")
}

// --- shared rendering ---

func printCustomers(customers []adminops.Customer) {
	if len(customers) == 0 {
		fmt.Println("  No customers.")
		return
	}
	tw := newTabWriter()
	fmt.Fprintln(tw, "  ID\tNAME\tPLAN\tACTIVE\tKEYS\tEMAIL\tLAST USED")
	for _, c := range customers {
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%d\t%s\t%s\n",
			c.ID, truncate(c.Name, 28), c.Plan, yesNo(c.Active), c.LiveKeys,
			dash(truncate(c.Email, 30)), relative(c.LastUsedAt))
	}
	_ = tw.Flush()
}

func printKeys(keys []adminops.Key) {
	tw := newTabWriter()
	fmt.Fprintln(tw, "  ID\tHASH PREFIX\tSTATE\tCREATED\tLAST USED")
	for _, k := range keys {
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\n",
			k.ID, k.HashPrefix, keyState(k.ExpiresAt, k.Expired(nowFunc())),
			k.CreatedAt.Format("2006-01-02"), relative(k.LastUsedAt))
	}
	_ = tw.Flush()
}
