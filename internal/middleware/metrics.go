package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/security-accelerated/intelligence-api/internal/metrics"
)

// Metrics returns middleware that records every request's latency by route
// template, method, status and plan.
//
// It must be the first middleware in the chain, ahead of gin.Recovery. The
// recording happens after c.Next() returns, and a panic unwinds past every
// middleware between it and Recovery without running that code: placed after
// Recovery, a panicking request would never be counted, and the 500s a
// dashboard most needs to see would be the ones missing from it.
func Metrics(m *metrics.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		// The route template, never the raw path: /v1/nope-1, /v1/nope-2, ...
		// would otherwise each become a series of their own.
		route := c.FullPath()
		if route == "" {
			route = metrics.RouteUnmatched
		}

		plan := metrics.PlanNone
		if v, ok := c.Get("api_key_plan"); ok {
			if s, ok := v.(string); ok && s != "" {
				plan = s
			}
		}

		m.ObserveHTTP(route, metricMethod(c.Request.Method), plan, c.Writer.Status(), time.Since(start))
	}
}

// metricMethod bounds the method label. net/http accepts any token as a
// method, so an unrecognized one is recorded as "other" rather than verbatim.
func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
		return method
	}
	return metrics.MethodOther
}
