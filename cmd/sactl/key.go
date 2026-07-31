package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/security-accelerated/intelligence-api/internal/billing"
	"github.com/security-accelerated/intelligence-api/internal/config"
)

func keyGroup() group {
	return group{
		name:    "key",
		summary: "inspect and rotate API keys",
		commands: []command{
			keyList(),
			keyRotate(),
		},
	}
}

type keyListFlags struct {
	db       *dbFlags
	customer int
}

func keyList() command {
	return command{
		name:    "list",
		summary: "list a customer's keys and their expiry state",
		usage:   "--customer N",
		flags: func(fs *flag.FlagSet) any {
			f := &keyListFlags{db: registerDBFlags(fs)}
			fs.IntVar(&f.customer, "customer", 0, "customer ID (required)")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*keyListFlags)
			if f.customer == 0 {
				return errors.New("--customer is required")
			}

			store, _, closeFn, err := f.db.openStore(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			keys, err := store.ListKeys(ctx, f.customer)
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				fmt.Printf("Customer %d has no keys.\n", f.customer)
				return nil
			}

			now := nowFunc()
			tw := newTabWriter()
			// The plaintext is never stored, so the hash prefix is all that can
			// be shown. It is enough to match a row against a key an operator
			// already holds, by hashing theirs and comparing.
			fmt.Fprintln(tw, "ID\tHASH PREFIX\tSTATE\tCREATED\tLAST USED")
			for _, k := range keys {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
					k.ID, k.HashPrefix, keyState(k.ExpiresAt, k.Expired(now)),
					k.CreatedAt.Format(time.DateOnly), relative(k.LastUsedAt))
			}
			return tw.Flush()
		},
	}
}

// keyState describes a key's position in the rotation lifecycle.
func keyState(expires time.Time, expired bool) string {
	switch {
	case expires.IsZero():
		return "active"
	case expired:
		return "expired"
	default:
		return "expiring " + relativeFuture(expires)
	}
}

func relativeFuture(t time.Time) string {
	d := time.Until(t)
	if d < time.Hour {
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	}
	return fmt.Sprintf("in %dh", int(d.Hours()))
}

type keyRotateFlags struct {
	db       *dbFlags
	customer int
}

func keyRotate() command {
	return command{
		name:    "rotate",
		summary: "issue a new key and grace-expire the customer's previous keys",
		usage:   "--customer N",
		flags: func(fs *flag.FlagSet) any {
			f := &keyRotateFlags{db: registerDBFlags(fs)}
			fs.IntVar(&f.customer, "customer", 0, "customer ID (required)")
			return f
		},
		run: func(ctx context.Context, cfg any, _ []string) error {
			f := cfg.(*keyRotateFlags)
			if f.customer == 0 {
				return errors.New("--customer is required")
			}

			db, target, err := f.db.openDB(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()

			grace := config.Config().GetDuration("auth.rotation_grace")
			if err := confirm(f.db, target, fmt.Sprintf(
				"Rotate the key for customer %d (previous keys stop working after %s)", f.customer, grace)); err != nil {
				return err
			}

			// Reuse the server's rotation service rather than reimplementing
			// it. Rotation is not a single INSERT: it mints a key, stores the
			// hash, and stamps a grace expiry on every previous key in one
			// transaction. A second implementation would drift from the one
			// the /v1/keys/rotate endpoint uses, and the drift would show up
			// as keys dying earlier or later than customers were told.
			//
			// The auth cache lives in the API process, not here, so there is
			// nothing local to invalidate; the note below covers the delay.
			svc := billing.NewKeyRotationService(billing.NewRepository(db), grace, noopCacheInvalidator{})

			rawKey, oldExpiry, err := svc.Rotate(ctx, f.customer)
			if err != nil {
				return err
			}

			fmt.Printf("\nRotated the key for customer %d.\n\n", f.customer)
			fmt.Printf("  API key: %s\n\n", rawKey)
			fmt.Println("This key is shown once and cannot be recovered — only its hash is stored.")
			fmt.Printf("Previous keys stop working at %s.\n", oldExpiry.Format(time.RFC3339))
			fmt.Println(planCacheNote)
			return nil
		},
	}
}

// noopCacheInvalidator satisfies the rotation service's dependency on the auth
// cache. That cache is in-process in the running API; the CLI is a separate
// process and has no cache of its own to clear.
type noopCacheInvalidator struct{}

func (noopCacheInvalidator) InvalidateAll() {}
