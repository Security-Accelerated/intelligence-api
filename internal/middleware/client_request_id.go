package middleware

import (
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// ClientRequestIDHeader is the HTTP header used to pass a client-supplied
	// correlation ID through the request/response cycle.
	ClientRequestIDHeader = "X-Client-Request-ID"

	// ClientRequestIDKey is the gin context key where the validated ID is stored.
	ClientRequestIDKey = "client_request_id"

	// ClientRequestIDMaxLen caps the accepted length after trimming whitespace.
	// Exported because it is part of the published contract: the docs pages
	// state this number, and a drift test asserts they still agree.
	ClientRequestIDMaxLen = 64
)

// safeClientIDPattern permits alphanumerics, hyphens, underscores, dots, and
// colons — the characters commonly found in UUIDs, trace IDs, and similar
// correlation identifiers.
var safeClientIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_.:]+$`)

// ClientRequestID reads X-Client-Request-ID from the incoming request, strips
// surrounding whitespace, and validates it. If the value passes validation it
// is stored in the gin context and echoed back as a response header. Invalid
// or missing values are silently ignored.
func ClientRequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimSpace(c.GetHeader(ClientRequestIDHeader))
		if raw == "" {
			c.Next()
			return
		}

		if len(raw) > ClientRequestIDMaxLen {
			c.Next()
			return
		}

		if !safeClientIDPattern.MatchString(raw) {
			c.Next()
			return
		}

		c.Set(ClientRequestIDKey, raw)
		c.Header(ClientRequestIDHeader, raw)
		c.Next()
	}
}
