package main

import (
	"errors"
	"fmt"
	"slices"
)

// allowWritesFlag is the global opt-in for anything that changes state.
//
// Read-only inspection is the common case and is what an operator reaches for
// when something looks wrong — often against production, often in a hurry. The
// mutating commands sit in the same binary one word away (`customer list` vs
// `customer plan`), so a typo or a recalled shell line can change data when the
// intent was to look at it. Requiring the flag makes every mutation a decision
// taken before the command is composed, not one confirmed after it is typed.
//
// It is deliberately a process-wide switch set once during argument parsing
// rather than a field threaded through every command: a mutation path that
// forgot to check a field would be silently unguarded, whereas there is exactly
// one place to consult here and requireWrites is the only reader.
var allowWrites bool

// writeFlagName is the flag operators are told to add. Kept in one place so the
// error message cannot drift from the flag itself.
const writeFlagName = "--allow-writes"

// errWritesDisabled is returned by requireWrites. Commands surface it unchanged.
var errWritesDisabled = errors.New("writes are disabled")

// requireWrites gates a mutating action. action is phrased as the thing being
// attempted, e.g. "create a customer".
func requireWrites(action string) error {
	if allowWrites {
		return nil
	}
	return fmt.Errorf("%w: refusing to %s. Re-run with %s to permit changes",
		errWritesDisabled, action, writeFlagName)
}

// extractGlobalFlags pulls the global switches out of the argument list and
// returns what remains.
//
// They are handled before subcommand dispatch so they work identically in every
// position — including `sactl --allow-writes` with no command at all, which
// starts the interactive menu with mutations enabled. Leaving it to each
// FlagSet would mean the interactive path, which parses no flags, could never
// enable writes.
func extractGlobalFlags(args []string) []string {
	rest := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case writeFlagName, "-allow-writes":
			allowWrites = true
		default:
			rest = append(rest, a)
		}
	}
	return rest
}

// mutatingCommands names every subcommand that changes state, as "group sub"
// or a bare command name. Used only to describe the gate in help output; the
// enforcement is requireWrites at each call site, so a command missing from
// this list is still gated.
var mutatingCommands = []string{
	"customer create",
	"customer plan",
	"customer rename",
	"customer activate",
	"customer deactivate",
	"key rotate",
}

func isMutating(name string) bool { return slices.Contains(mutatingCommands, name) }
