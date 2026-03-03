package auth

import "time"

type Customer struct {
	ID        int
	APIKeyID  int
	Name      string
	Active    bool
	Tier      string
	Features  []string
	CreatedAt time.Time
}
