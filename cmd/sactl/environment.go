package main

// environment is a coherent target: an API host and the database that backs it.
//
// These have to move together. Pointing --host at localhost while the database
// flags still point at Neon produces a session that reads one deployment and
// writes another — it caught me twice before this existed. Selecting an
// environment switches both at once, so a target is never half-applied.
type environment struct {
	name string
	// apiHost is the base URL for every HTTP command.
	apiHost string
	// databaseURL is the connection string, empty to use the postgres.* keys.
	databaseURL string
	// description is shown when switching, so the choice is unambiguous.
	description string
}

const (
	envProduction = "production"
	envLocal      = "local"
)

// localDatabaseURL matches the credentials in docker-compose.yaml. sslmode is
// disabled because the local container serves plaintext, unlike Neon.
//
// These are not a secret: they are the same fixed values docker-compose.yaml
// puts in the repo, they only ever reach a container on localhost, and no
// deployed environment uses them — production credentials come from .env.
//
//nolint:gosec // G101: local docker-compose credentials, not a real secret.
const localDatabaseURL = "postgres://intelligence:intelligence@localhost:5432/intelligence_api?sslmode=disable"

func environments() []environment {
	return []environment{
		{
			name:        envProduction,
			apiHost:     defaultHost,
			description: "the deployed API and Neon; credentials from .env",
		},
		{
			name:        envLocal,
			apiHost:     "http://localhost:8080",
			databaseURL: localDatabaseURL,
			description: "the docker compose stack; no .env needed",
		},
	}
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
