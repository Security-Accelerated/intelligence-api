package auth

import "time"

type Customer struct {
	ID        int
	Name      string
	Active    bool
	Tier      string
	Roles     []string
	CreatedAt time.Time
}
