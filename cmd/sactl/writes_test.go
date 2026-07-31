package main

import (
	"errors"
	"strings"
	"testing"
)

func TestExtractGlobalFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
		on   bool
	}{
		{"absent", []string{"customer", "list"}, []string{"customer", "list"}, false},
		{"long form", []string{"--allow-writes", "customer", "create"}, []string{"customer", "create"}, true},
		{"single dash", []string{"-allow-writes", "customer", "create"}, []string{"customer", "create"}, true},
		{"trailing position", []string{"key", "rotate", "--allow-writes"}, []string{"key", "rotate"}, true},
		{"no command at all", []string{"--allow-writes"}, []string{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowWrites = false
			defer func() { allowWrites = false }()

			got := extractGlobalFlags(tc.args)
			if allowWrites != tc.on {
				t.Errorf("allowWrites = %v, want %v", allowWrites, tc.on)
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("remaining args = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRequireWrites_NamesTheFlag matters because the error is the only place an
// operator learns how to proceed. A bare "not permitted" would send them to the
// source.
func TestRequireWrites_NamesTheFlag(t *testing.T) {
	allowWrites = false
	err := requireWrites("rotate the key for customer 3")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, errWritesDisabled) {
		t.Errorf("error does not wrap errWritesDisabled: %v", err)
	}
	for _, want := range []string{writeFlagName, "rotate the key for customer 3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	allowWrites = true
	defer func() { allowWrites = false }()
	if err := requireWrites("anything"); err != nil {
		t.Errorf("writes enabled but still refused: %v", err)
	}
}

// TestMutatingCommandsAreGated is a checklist guard: every command named as
// mutating must actually call requireWrites. The list is documentation, but a
// command added to it without a gate would read as protected while not being.
func TestMutatingCommandsAreGated(t *testing.T) {
	for _, name := range mutatingCommands {
		if !isMutating(name) {
			t.Errorf("%q is in mutatingCommands but isMutating says otherwise", name)
		}
	}
	if isMutating("customer list") {
		t.Error("customer list is read-only but reports as mutating")
	}
}
