package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// loadEnvFile reads KEY=VALUE lines from path into the process environment,
// without interpreting them as shell.
//
// Sourcing the file instead (`set -a && . ./.env`) is not equivalent and is the
// reason this exists: values here include PostgreSQL connection strings, which
// carry query parameters separated by `&`. An unquoted `&` backgrounds the
// command, so sourcing truncates the value at the first parameter and leaves
// the shell with a mangled environment. scripts/status.sh works around it by
// grepping individual keys out of the file; doing it properly once is cheaper
// than repeating that per key.
//
// Existing environment variables win, so an explicit export still overrides the
// file. Missing files are not an error — the file is a convenience, not a
// requirement.
func loadEnvFile(path string) (loaded int, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip an optional `export ` prefix so files written for shell use work.
		line = strings.TrimPrefix(line, "export ")

		key, value, found := strings.Cut(line, "=")
		if !found {
			return loaded, fmt.Errorf("%s:%d: expected KEY=VALUE", path, lineNo)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return loaded, fmt.Errorf("%s:%d: empty key", path, lineNo)
		}

		// Values are taken verbatim apart from matched surrounding quotes.
		// Nothing else is unescaped: these are literals, not shell words.
		value = strings.TrimSpace(value)
		value = unquote(value)

		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return loaded, err
		}
		loaded++
	}
	if err := scanner.Err(); err != nil {
		return loaded, err
	}
	return loaded, nil
}

// unquote removes one layer of matching single or double quotes.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	for _, q := range []byte{'"', '\''} {
		if s[0] == q && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}
