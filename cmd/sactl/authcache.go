package main

import (
	"context"
	"fmt"
	"os"
)

// invalidateAuthCache asks the running API to drop its cached customer lookups.
//
// The API caches auth by key hash for auth.cache_ttl (5m by default), so a plan
// or activation change made in the database is invisible to the service until
// that entry expires. Printing a note telling the operator to go and invalidate
// it themselves put a required step behind a paragraph of prose — and an
// operator watching for the new limits to take effect reasonably concludes the
// command silently failed.
//
// Failure is reported, not fatal: the change is already committed, and the
// cache expires on its own. The distinction matters, so the message says which
// happened rather than implying the whole operation failed.
func invalidateAuthCache(ctx context.Context, api *apiFlags) {
	if api == nil {
		return
	}
	if _, err := api.adminKey(); err != nil {
		fmt.Fprintf(os.Stderr,
			"sactl: change applied, but the auth cache was not invalidated (%v).\n       It clears on its own within auth.cache_ttl.\n", err)
		return
	}

	if err := api.postNoBody(ctx, "/v1/admin/auth/cache/invalidate"); err != nil {
		fmt.Fprintf(os.Stderr,
			"sactl: change applied, but the auth cache was not invalidated (%v).\n       It clears on its own within auth.cache_ttl.\n", err)
		return
	}
	fmt.Println("Auth cache invalidated; the change is live now.")
}
