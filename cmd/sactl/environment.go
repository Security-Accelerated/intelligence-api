package main

import (
	"fmt"
	"strings"
)

// environment is a coherent target: an API host, a database, and the keys that
// work against both.
//
// These three have to move together. Pointing --host at localhost while the
// keys still come from .env produces 401s that look like a broken deployment —
// it caught me twice before this existed. Selecting an environment switches all
// of them at once, so a target is never half-applied.
type environment struct {
	name string
	// apiHost is the base URL for every HTTP command.
	apiHost string
	// databaseURL is the connection string, empty to use the postgres.* keys.
	databaseURL string
	// keys are the smoke-suite credentials valid against this environment.
	keys smokeKeys
	// useEnvFileKeys takes credentials from the environment rather than from
	// the literals below. Production keys are secrets and are never in source.
	useEnvFileKeys bool
	// description is shown when switching, so the choice is unambiguous.
	description string
}

const (
	envProduction = "production"
	envLocal      = "local"
)

// localDevKeys are the plaintext API keys created by migrations/seed.sql.
//
// Committing them is safe and deliberate: they only ever exist in a local
// container seeded from that file, and having them here means `sactl` works
// against a freshly reset stack with no configuration at all. Anything that
// reads them for a deployed environment is a bug, which is why they are only
// reachable through the local environment.
var localDevKeys = smokeKeys{
	pools: map[string]*keyPool{
		"admin": {keys: []string{"test-admin-key"}},
		"basic": {keys: []string{"test-basic-key"}},
		"pro":   {keys: []string{"test-pro-key"}},
		// Pooled, matching production, so a local run is not slowed by the
		// per-key rate limit. seed.sql provides these.
		"free": {keys: []string{"test-free-key", "test-free-key-2", "test-free-key-3"}},
	},
	rateLimit: "test-free-key-4",
}

// localDatabaseURL matches the credentials in docker-compose.yaml. sslmode is
// disabled because the local container serves plaintext, unlike Neon.
const localDatabaseURL = "postgres://intelligence:intelligence@localhost:5432/intelligence_api?sslmode=disable"

func environments() []environment {
	return []environment{
		{
			name:           envProduction,
			apiHost:        defaultHost,
			useEnvFileKeys: true,
			description:    "the deployed API and Neon; credentials from .env",
		},
		{
			name:        envLocal,
			apiHost:     "http://localhost:8080",
			databaseURL: localDatabaseURL,
			keys:        localDevKeys,
			description: "the docker compose stack; seeded dev keys, no .env needed",
		},
	}
}

func environmentNamed(name string) (environment, error) {
	for _, e := range environments() {
		if strings.EqualFold(e.name, name) {
			return e, nil
		}
	}
	return environment{}, fmt.Errorf("unknown environment %q; choose one of: %s",
		name, strings.Join(environmentNames(), ", "))
}

func environmentNames() []string {
	var out []string
	for _, e := range environments() {
		out = append(out, e.name)
	}
	return out
}

// resolveKeys returns the credentials for this environment. Production reads
// the environment; local uses the seeded literals, so it works with no setup.
func (e environment) resolveKeys(f *smokeFlags) smokeKeys {
	if !e.useEnvFileKeys {
		return e.keys
	}
	return resolveSmokeKeys(f)
}

// apply points the API and database flags at this environment.
func (e environment) apply(api *apiFlags, db *dbFlags) {
	if api != nil {
		api.host = e.apiHost
	}
	if db != nil {
		// Assigned unconditionally, including the empty string production uses.
		// Switching local -> production has to clear the local URL so the
		// POSTGRES_URL / NEON_CONNECTION_STRING lookup resumes; leaving a stale
		// value would keep a "production" session pointed at the container.
		db.databaseURL = e.databaseURL
	}
}
