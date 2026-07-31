package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/security-accelerated/intelligence-api/internal/adminops"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/database"
	"github.com/spf13/viper"
)

// dbFlags are shared by every command that talks to PostgreSQL directly.
type dbFlags struct {
	databaseURL string
	yes         bool
}

func registerDBFlags(fs *flag.FlagSet) *dbFlags {
	f := &dbFlags{}
	fs.StringVar(&f.databaseURL, "database-url", "",
		"PostgreSQL connection string; overrides POSTGRES_* config (e.g. \"$NEON_CONNECTION_STRING\")")
	fs.BoolVar(&f.yes, "yes", false, "skip the confirmation prompt for a mutating command")
	return f
}

// dsnEnvVars are the environment variables checked for a connection string,
// in order, when --database-url is not given.
//
// POSTGRES_URL is the server's own key. The other two are here because a
// managed provider's console hands out one string and operators paste it into
// .env under whatever name the provider used; requiring it to be renamed just
// to use the CLI is friction with no benefit. The order means an explicit
// POSTGRES_URL always beats a provider-specific leftover.
var dsnEnvVars = []string{"POSTGRES_URL", "DATABASE_URL", "NEON_CONNECTION_STRING"}

// viperFor returns the resolved configuration, applying the --database-url
// override on top of the server's own config sources.
func (f *dbFlags) viperFor() *viper.Viper {
	cfg := config.Config()

	if url := strings.TrimSpace(f.databaseURL); url != "" {
		cfg.Set("postgres.url", url)
		return cfg
	}
	for _, name := range dsnEnvVars {
		if url := strings.TrimSpace(os.Getenv(name)); url != "" {
			cfg.Set("postgres.url", url)
			return cfg
		}
	}
	return cfg
}

// openStore connects and returns the admin store plus the connection's close
// function. target is a redacted description of the database, for prompts.
func (f *dbFlags) openStore(ctx context.Context) (store *adminops.Store, target string, closeFn func(), err error) {
	cfg := f.viperFor()
	target = database.Describe(cfg)

	db, closeDB, err := database.Open(ctx, cfg)
	if err != nil {
		return nil, target, nil, fmt.Errorf("connect to postgres (%s): %w", target, err)
	}
	return adminops.NewStore(db), target, func() { _ = closeDB() }, nil
}

// openDB is openStore for the commands that need the raw handle, currently key
// rotation, which reuses the server's own rotation service.
func (f *dbFlags) openDB(ctx context.Context) (db *sql.DB, closeDB func() error, target string, err error) {
	cfg := f.viperFor()
	target = database.Describe(cfg)

	db, closeDB, err = database.Open(ctx, cfg)
	if err != nil {
		return nil, nil, target, fmt.Errorf("connect to postgres (%s): %w", target, err)
	}
	return db, closeDB, target, nil
}

// confirm asks before a mutating operation, naming the database it will change.
//
// The CLI reads the same environment the server does, so the difference between
// a local database and production is one exported variable. Printing the target
// makes that visible at the moment it matters. --yes skips the prompt for
// scripted use; a non-interactive stdin without --yes is refused rather than
// assumed to mean yes.
func confirm(f *dbFlags, target, action string) error {
	if f.yes {
		return nil
	}

	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 {
		return fmt.Errorf("%s on %s needs confirmation; pass --yes to proceed without a prompt", action, target)
	}

	fmt.Printf("%s\n  database: %s\nProceed? [y/N] ", action, target)
	var answer string
	_, _ = fmt.Scanln(&answer)
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	default:
		return fmt.Errorf("aborted")
	}
}
