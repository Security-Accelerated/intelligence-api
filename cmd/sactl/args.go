package main

import (
	"flag"
	"strings"
)

// reorderArgs moves flags ahead of positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
//
//	sactl lookup domain example.com --lookups dns,ssl
//
// silently ignores --lookups: it becomes a positional, the defaults are used,
// and the command reports success having done something other than what was
// asked. That is worse than an error, and the ordering rule is invisible —
// every other CLI an operator uses accepts flags in any position.
//
// Reordering needs to know which flags consume the following argument, or
// `--lookups dns` would move --lookups and leave dns behind as a target. That
// comes from the FlagSet: boolean flags are self-contained, everything else
// takes a value.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// "--" ends flag parsing entirely; everything after is positional.
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		flags = append(flags, arg)

		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			// --flag=value carries its own value.
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			// Unknown flag: leave it for Parse to reject with its own message
			// rather than guessing whether it consumes the next argument.
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}

	if len(positional) == 0 {
		return flags
	}
	// Separate the two groups explicitly. Without it a positional that begins
	// with a dash — which is the whole reason "--" exists — would be re-parsed
	// as a flag once it had been moved behind the real ones.
	return append(append(flags, "--"), positional...)
}
