package auth

import "time"

type APIKey struct {
	ID        int
	Key       string
	Role      string
	Active    bool
	CreatedAt time.Time
}
