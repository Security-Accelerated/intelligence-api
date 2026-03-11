package auth

import "time"

type Customer struct {
	ID        int
	APIKeyID  int
	Name      string
	Active    bool
	Plan      string
	CreatedAt time.Time
}
