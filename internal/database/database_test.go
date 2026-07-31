package database

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func cfgWith(kv map[string]any) *viper.Viper {
	v := viper.New()
	for k, val := range kv {
		v.Set(k, val)
	}
	return v
}

func TestDSN_BuildsFromParts(t *testing.T) {
	got := DSN(cfgWith(map[string]any{
		"postgres.host":     "db.internal",
		"postgres.port":     5432,
		"postgres.user":     "svc",
		"postgres.password": "secret",
		"postgres.dbname":   "intel",
		"postgres.sslmode":  "require",
	}))

	for _, want := range []string{"postgres://", "svc:secret@db.internal:5432", "/intel", "sslmode=require"} {
		if !strings.Contains(got, want) {
			t.Errorf("DSN = %q, missing %q", got, want)
		}
	}
}

// TestDSN_EncodesReservedCharacters guards the reason the URL is built with
// net/url rather than fmt.Sprintf: a password containing @ or / would otherwise
// terminate the userinfo section early and produce a DSN pointing somewhere
// else entirely.
func TestDSN_EncodesReservedCharacters(t *testing.T) {
	got := DSN(cfgWith(map[string]any{
		"postgres.host":     "db.internal",
		"postgres.port":     5432,
		"postgres.user":     "svc",
		"postgres.password": "p@ss/w#rd",
		"postgres.dbname":   "intel",
		"postgres.sslmode":  "require",
	}))

	if strings.Contains(got, "p@ss/w#rd") {
		t.Errorf("DSN = %q, password was not percent-encoded", got)
	}
	if !strings.Contains(got, "@db.internal:5432") {
		t.Errorf("DSN = %q, host is not where it should be", got)
	}
}

// TestDSN_URLWins covers managed providers. Neon's connection string carries
// pooler and endpoint parameters in its query string; rebuilding it from
// host/user/password/dbname silently drops them, and the result fails to
// authenticate rather than reporting missing configuration.
func TestDSN_URLWins(t *testing.T) {
	full := "postgres://u:p@ep-x-pooler.aws.neon.tech/neondb?sslmode=require&options=endpoint%3Dep-x"
	got := DSN(cfgWith(map[string]any{
		"postgres.url":  full,
		"postgres.host": "ignored.example.com",
		"postgres.user": "ignored",
	}))
	if got != full {
		t.Errorf("DSN = %q, want the configured URL verbatim", got)
	}
}

func TestDSN_BlankURLFallsBackToParts(t *testing.T) {
	got := DSN(cfgWith(map[string]any{
		"postgres.url":  "   ",
		"postgres.host": "db.internal",
		"postgres.port": 5432,
	}))
	if !strings.Contains(got, "db.internal") {
		t.Errorf("DSN = %q, a whitespace-only URL should fall back to the parts", got)
	}
}

// TestDescribe_OmitsCredentials matters because admin tooling prints this
// before mutating a database, often with the output pasted into a ticket or a
// chat. Leaking the password there would be worse than not printing anything.
func TestDescribe_OmitsCredentials(t *testing.T) {
	got := Describe(cfgWith(map[string]any{
		"postgres.url": "postgres://admin:hunter2@db.example.com:5432/intel?sslmode=require",
	}))

	if strings.Contains(got, "hunter2") || strings.Contains(got, "admin") {
		t.Fatalf("Describe = %q, it leaks credentials", got)
	}
	if got != "db.example.com:5432/intel" {
		t.Errorf("Describe = %q, want host and database name", got)
	}
}

func TestDescribe_Unparseable(t *testing.T) {
	got := Describe(cfgWith(map[string]any{"postgres.url": "://not a url"}))
	if got == "" || strings.Contains(got, "not a url") {
		t.Errorf("Describe = %q, want a safe placeholder", got)
	}
}

// TestDescribe_NoConfiguration distinguishes "nothing configured" from a
// malformed value. Both used to render identically, which sent an operator
// looking for a typo in a string they had never set.
func TestDescribe_NoConfiguration(t *testing.T) {
	got := Describe(viper.New())
	if got != "(no database configured)" {
		t.Errorf("Describe = %q, want an explicit 'not configured' message", got)
	}
}
