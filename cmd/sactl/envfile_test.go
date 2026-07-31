package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadEnvFile_ConnectionStringWithAmpersand is the case that motivated this
// function. `set -a && . ./.env` backgrounds at the unquoted `&`, so the value
// arrives truncated at the first query parameter — and a Neon DSN missing its
// endpoint parameter fails to authenticate rather than reporting bad config.
func TestLoadEnvFile_ConnectionStringWithAmpersand(t *testing.T) {
	const dsn = "postgres://u:p@ep-x-pooler.aws.neon.tech/neondb?sslmode=require&options=endpoint%3Dep-x&connect_timeout=10"
	path := writeEnv(t, "NEON_CONNECTION_STRING="+dsn+"\n")

	t.Setenv("NEON_CONNECTION_STRING", "")
	os.Unsetenv("NEON_CONNECTION_STRING")

	if _, err := loadEnvFile(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := os.Getenv("NEON_CONNECTION_STRING"); got != dsn {
		t.Errorf("got %q,\nwant %q", got, dsn)
	}
}

func TestLoadEnvFile_ParsesFormatting(t *testing.T) {
	path := writeEnv(t, `
# a comment
EMPTY_LINES_ABOVE=1

QUOTED="double quoted"
SINGLE='single quoted'
export EXPORTED=yes
SPACED  =  padded
EQUALS_IN_VALUE=a=b=c
`)
	for _, k := range []string{"EMPTY_LINES_ABOVE", "QUOTED", "SINGLE", "EXPORTED", "SPACED", "EQUALS_IN_VALUE"} {
		os.Unsetenv(k)
		t.Cleanup(func() { os.Unsetenv(k) })
	}

	n, err := loadEnvFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 6 {
		t.Errorf("loaded %d keys, want 6", n)
	}

	for _, tc := range []struct{ key, want string }{
		{"EMPTY_LINES_ABOVE", "1"},
		{"QUOTED", "double quoted"},
		{"SINGLE", "single quoted"},
		{"EXPORTED", "yes"},
		{"SPACED", "padded"},
		{"EQUALS_IN_VALUE", "a=b=c"},
	} {
		if got := os.Getenv(tc.key); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
}

// TestLoadEnvFile_ExistingEnvWins keeps an explicit export authoritative. An
// operator pointing the CLI at a different database for one command must not
// have the file silently put it back.
func TestLoadEnvFile_ExistingEnvWins(t *testing.T) {
	path := writeEnv(t, "TARGET=from-file\n")
	t.Setenv("TARGET", "from-environment")

	if _, err := loadEnvFile(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := os.Getenv("TARGET"); got != "from-environment" {
		t.Errorf("TARGET = %q, want the exported value to win", got)
	}
}

func TestLoadEnvFile_MissingFileIsNotAnError(t *testing.T) {
	n, err := loadEnvFile(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("loaded %d keys from a missing file", n)
	}
}

func TestLoadEnvFile_MalformedLine(t *testing.T) {
	path := writeEnv(t, "GOOD=1\nthis line has no equals sign\n")
	if _, err := loadEnvFile(path); err == nil {
		t.Fatal("expected an error for a line with no '='")
	}
}
