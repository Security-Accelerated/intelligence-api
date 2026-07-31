package handler

// Exported views of the plan-gating tables.
//
// These exist for the smoke suite in cmd/sactl, which derives its plan
// permutation matrix from them rather than restating it. A restated copy would
// drift the moment a lookup was added or re-tiered, and the drift would be
// invisible: the suite would keep passing while testing the old contract.
// Deriving means a new lookup gets full per-plan coverage the day it ships.
//
// They are functions rather than exported maps so callers cannot mutate the
// tables the request path reads from.

// DomainLookupAllowed reports whether plan may request lookupName on
// /v1/domain/lookup. known is false when the name is not a domain lookup at
// all, which the handler answers with 400 rather than 403 — a distinction the
// smoke suite asserts, since collapsing the two would hide a lookup silently
// disappearing from the catalog.
func DomainLookupAllowed(plan, lookupName string) (allowed, known bool) {
	return allowedFor(lookupMinPlan, plan, lookupName)
}

// IPLookupAllowed is DomainLookupAllowed for /v1/ip/lookup.
func IPLookupAllowed(plan, lookupName string) (allowed, known bool) {
	return allowedFor(ipLookupMinPlan, plan, lookupName)
}

func allowedFor(table map[string]string, plan, lookupName string) (allowed, known bool) {
	minPlan, ok := table[lookupName]
	if !ok {
		return false, false
	}
	// Mirrors the request path exactly: an unrecognized plan ranks 0, the least
	// privileged, rather than erroring.
	return planRank[plan] >= planRank[minPlan], true
}
