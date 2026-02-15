package auth

import "time"

type Customer struct {
	ID        int
	Name      string
	Active    bool
	Roles     []string
	CreatedAt time.Time
}
