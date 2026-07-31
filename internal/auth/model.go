package auth

import (
	"slices"
	"time"
)

// Plan names, in order of increasing capability. They live here rather than in
// the HTTP layer because a plan is a property of the customer: the admin CLI
// sets it and the auth lookup returns it, and neither involves a request.
const (
	PlanFree  = "free"
	PlanBasic = "basic"
	PlanPro   = "pro"
	PlanAdmin = "admin"
)

// Plans lists every valid plan, least privileged first. Callers that rank plans
// by capability rely on that order.
var Plans = []string{PlanFree, PlanBasic, PlanPro, PlanAdmin}

// ValidPlan reports whether name is a recognized plan. Plans are rejected at
// the point they are set rather than silently degrading to the least privileged
// plan, which is what request-time gating does with an unknown value.
func ValidPlan(name string) bool {
	return slices.Contains(Plans, name)
}

type Customer struct {
	ID        int
	APIKeyID  int
	Name      string
	Active    bool
	Plan      string
	CreatedAt time.Time
}
