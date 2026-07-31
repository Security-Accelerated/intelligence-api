package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/adminops"
	"github.com/security-accelerated/intelligence-api/internal/auth"
)

func customerGroup() group {
	return group{
		name:    "customer",
		summary: "create and manage customers",
		commands: []command{
			customerCreate(),
			customerList(),
			customerPlan(),
			customerActive("activate", true),
			customerActive("deactivate", false),
		},
	}
}

type customerCreateFlags struct {
	db    *dbFlags
	name  string
	email string
	plan  string
}

func customerCreate() command {
	return command{
		name:    "create",
		summary: "create a customer and issue its first API key",
		usage:   "--name NAME --plan PLAN [--email EMAIL]",
		flags: func(fs *flag.FlagSet) any {
			f := &customerCreateFlags{db: registerDBFlags(fs)}
			fs.StringVar(&f.name, "name", "", "customer name (required)")
			fs.StringVar(&f.email, "email", "", "contact email")
			fs.StringVar(&f.plan, "plan", auth.PlanFree,
				fmt.Sprintf("plan: %s", strings.Join(auth.Plans, ", ")))
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*customerCreateFlags)
			if strings.TrimSpace(f.name) == "" {
				return errors.New("--name is required")
			}
			// Validate before connecting: an unknown plan should not cost a
			// round trip, and the error should name the valid values.
			if !auth.ValidPlan(f.plan) {
				return fmt.Errorf("invalid plan %q; valid plans: %s", f.plan, strings.Join(auth.Plans, ", "))
			}
			if err := requireWrites(fmt.Sprintf("create customer %q", f.name)); err != nil {
				return err
			}

			store, target, closeFn, err := f.db.openStore(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			if err := confirm(f.db, target, fmt.Sprintf("Create customer %q on the %s plan", f.name, f.plan)); err != nil {
				return err
			}

			id, rawKey, err := store.CreateCustomer(ctx, f.name, f.email, f.plan)
			if err != nil {
				return err
			}

			fmt.Printf("\nCreated customer %d (%s) on the %s plan.\n\n", id, f.name, f.plan)
			fmt.Printf("  API key: %s\n\n", rawKey)
			// Only the sha256 digest is stored, so this is genuinely the only
			// time the key can be read. Saying so here is cheaper than the
			// rotation an operator would otherwise have to perform.
			fmt.Println("This key is shown once and cannot be recovered — only its hash is stored.")
			fmt.Println("If it is lost, issue a new one with: sactl key rotate --customer", id)
			return nil
		},
	}
}

type customerListFlags struct {
	db *dbFlags
}

func customerList() command {
	return command{
		name:    "list",
		summary: "list customers with their plan and key state",
		flags: func(fs *flag.FlagSet) any {
			return &customerListFlags{db: registerDBFlags(fs)}
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*customerListFlags)

			store, _, closeFn, err := f.db.openStore(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			customers, err := store.ListCustomers(ctx)
			if err != nil {
				return err
			}
			if len(customers) == 0 {
				fmt.Println("No customers.")
				return nil
			}

			tw := newTabWriter()
			fmt.Fprintln(tw, "ID\tNAME\tPLAN\tACTIVE\tKEYS\tEMAIL\tCREATED\tLAST USED")
			for _, c := range customers {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					c.ID, truncate(c.Name, 28), c.Plan, yesNo(c.Active), c.LiveKeys,
					dash(truncate(c.Email, 30)), c.CreatedAt.Format(time.DateOnly), relative(c.LastUsedAt))
			}
			return tw.Flush()
		},
	}
}

type customerPlanFlags struct {
	db   *dbFlags
	api  *apiFlags
	id   int
	plan string
}

func customerPlan() command {
	return command{
		name:    "plan",
		summary: "change a customer's plan",
		usage:   "--id N --plan PLAN",
		flags: func(fs *flag.FlagSet) any {
			f := &customerPlanFlags{db: registerDBFlags(fs), api: registerAPIFlags(fs)}
			fs.IntVar(&f.id, "id", 0, "customer ID (required)")
			fs.StringVar(&f.plan, "plan", "", fmt.Sprintf("new plan: %s", strings.Join(auth.Plans, ", ")))
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*customerPlanFlags)
			if f.id == 0 {
				return errors.New("--id is required")
			}
			if !auth.ValidPlan(f.plan) {
				return fmt.Errorf("invalid plan %q; valid plans: %s", f.plan, strings.Join(auth.Plans, ", "))
			}
			if err := requireWrites(fmt.Sprintf("change customer %d to the %s plan", f.id, f.plan)); err != nil {
				return err
			}

			store, target, closeFn, err := f.db.openStore(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			if err := confirm(f.db, target, fmt.Sprintf("Move customer %d to the %s plan", f.id, f.plan)); err != nil {
				return err
			}

			if err := store.SetPlan(ctx, f.id, f.plan); err != nil {
				if errors.Is(err, adminops.ErrNotFound) {
					return fmt.Errorf("no customer with ID %d", f.id)
				}
				return err
			}

			fmt.Printf("Customer %d is now on the %s plan.\n", f.id, f.plan)
			invalidateAuthCache(ctx, f.api)
			return nil
		},
	}
}

// planCacheNote explains the delay when the cache could not be invalidated
// automatically. Without it, an operator watching for the new limits concludes
// the command silently failed.
const planCacheNote = "The API caches customer lookups, so this takes effect within auth.cache_ttl " +
	"(default 5m)."

type customerActiveFlags struct {
	db  *dbFlags
	api *apiFlags
	id  int
}

func customerActive(name string, active bool) command {
	verb := "Deactivate"
	if active {
		verb = "Activate"
	}
	return command{
		name:    name,
		summary: strings.ToLower(verb) + " a customer without deleting anything",
		usage:   "--id N",
		flags: func(fs *flag.FlagSet) any {
			f := &customerActiveFlags{db: registerDBFlags(fs), api: registerAPIFlags(fs)}
			fs.IntVar(&f.id, "id", 0, "customer ID (required)")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*customerActiveFlags)
			if f.id == 0 {
				return errors.New("--id is required")
			}
			if err := requireWrites(fmt.Sprintf("%s customer %d", strings.ToLower(verb), f.id)); err != nil {
				return err
			}

			store, target, closeFn, err := f.db.openStore(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			if err := confirm(f.db, target, fmt.Sprintf("%s customer %d", verb, f.id)); err != nil {
				return err
			}

			if err := store.SetActive(ctx, f.id, active); err != nil {
				if errors.Is(err, adminops.ErrNotFound) {
					return fmt.Errorf("no customer with ID %d", f.id)
				}
				return err
			}

			fmt.Printf("Customer %d is now %s.\n", f.id, map[bool]string{true: "active", false: "inactive"}[active])
			invalidateAuthCache(ctx, f.api)
			return nil
		},
	}
}

// relative renders a timestamp as an approximate age, or "never" when zero.
// Exact timestamps are rarely what an operator scanning a list wants, and they
// make the column wide enough to wrap.
func relative(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
