package billing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateAPIKey generates a cryptographically random 64-character hex API key.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate API key: %w", err)
	}
	return hex.EncodeToString(b), nil
}
