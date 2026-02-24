package domain

import (
	"context"
	"fmt"
)

// LookupTyposquatting generates typosquatting permutations for a domain and
// optionally checks registration/liveness. The timeout from opts.Timeout
// should already be applied to the parent context by the caller.
func LookupTyposquatting(ctx context.Context, domainName string, opts TyposquattingOptions) (*TyposquattingResponse, error) {
	depth := opts.Depth
	if depth == "" {
		depth = "shallow"
	}
	if depth != "shallow" && depth != "deep" {
		return nil, fmt.Errorf("invalid depth %q: must be \"shallow\" or \"deep\"", depth)
	}

	maxPerms := opts.MaxPermutations
	if maxPerms <= 0 {
		maxPerms = 500
	}

	perms, capped := GeneratePermutations(domainName, depth, maxPerms)

	if opts.Active && len(perms) > 0 {
		CheckActive(ctx, perms, opts.Concurrency)
	}

	return &TyposquattingResponse{
		Domain:       domainName,
		Depth:        depth,
		Count:        len(perms),
		Capped:       capped,
		Permutations: perms,
	}, nil
}
