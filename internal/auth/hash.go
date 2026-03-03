package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashKey returns the hex-encoded SHA-256 hash of a raw API key.
// SHA-256 is appropriate here (rather than bcrypt) because API keys are
// high-entropy random strings that don't need slow hashing, and we need
// fast O(1) lookups per request.
func HashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
