# Plan: Fix MEDIUM and LOW Security Audit Findings

## MEDIUM Findings

### 8. Security response headers — `internal/middleware/security_headers.go`

New middleware that sets on every response:
- `X-Content-Type-Options: nosniff`
- `Cache-Control: no-store`
- `X-Frame-Options: DENY`

Wire into router before all routes. Test in `security_headers_test.go`.

### 9. Request body size limit — `internal/middleware/body_limit.go`

New middleware using `http.MaxBytesReader` to cap request bodies at 1 MB.
Returns 413 Payload Too Large on overflow. Wire into router. Test in `body_limit_test.go`.

### 10. Unchecked type assertions in request logger — `internal/middleware/request_logger.go`

Replace bare `.()` assertions with comma-ok pattern:
- `apiKeyID.(int)` → safe cast with ok check
- `tier.(string)` → safe cast with ok check
- `roles.([]string)` → safe cast with ok check
- `val.(bool)` in ContextKeys loop → safe cast with ok check

### 11. Lookup failures not logged server-side — `internal/service/domain.go`, `typosquatting.go`

Add `logging.Logger().Warn("lookup failed", ...)` in every error branch alongside
the existing `resp.Errors = append(...)` so failures appear in server logs.

### 12. Auth failures not logged — `internal/middleware/auth.go`

Add warn log with `client_ip`, `path`, and reason when auth fails (missing key, invalid key).
Use `RequestLoggerWithLogger` pattern: add `AuthWithLogger` for testability.

### 13. DB errors in auth return 401 instead of 500 — `internal/middleware/auth.go`

Distinguish `sql.ErrNoRows` (→ 401 "invalid API key") from other DB errors (→ 500 "internal error").
Import `database/sql` and `errors`.

### 14. Redis client never closed — `internal/cache/redis.go` + `internal/app/app.go`

Add `Close() error` method to `RedisCache`. Defer `redisCache.Close()` in `app.go` after creation.

### 15. No Redis ping at startup — `internal/cache/redis.go` + `internal/app/app.go`

Add `Ping(ctx) error` method to `RedisCache`. Call it in `app.go` after creating the cache,
log success. Return error if ping fails (non-fatal warning, not hard failure since cache
is non-critical — actually, rate limiter needs it, so treat as fatal).

### 16. http.Transport created per call — `internal/domain/`

Create package-level shared transports in a new `internal/domain/transport.go`:
- `safeTransport` — with InsecureSkipVerify + safenet dialer, 10s timeout
- `safeFastTransport` — same but 2s timeout (for typosquatting)

Use in `headers.go`, `screenshot.go`, `typosquatting_active.go`. `ssl.go` uses tls.Dialer
directly (not http.Transport) so no change needed there.

### 19. No shutdown/serve tests — `internal/httpapi/server_test.go`

Table-driven tests:
- Normal shutdown on SIGTERM → returns nil
- Server listen error → returns error
- Graceful drain of in-flight requests

---

## LOW Findings

### 20. Dead os.Exit(1) — `cmd/api/main.go`

Remove `os.Exit(1)` after `logger.Fatal()` (Fatal already calls os.Exit).

### 21. errors.Is for redis.Nil — `internal/cache/redis.go`

Change `err == redis.Nil` to `errors.Is(err, redis.Nil)`.

### 22. Log level by status code — `internal/middleware/request_logger.go`

After building fields, use `logger.Warn` for 4xx and `logger.Error` for 5xx instead of
always `logger.Info`.

### 23. request_id propagation — `internal/middleware/request_logger.go`

Store `request_id` in context via `c.Set("request_id", requestID)` so downstream code
can include it in logs. (Propagation into service-layer logs is a follow-up.)

### 24. Response size logged — `internal/middleware/request_logger.go`

Add `zap.Int("response_bytes", c.Writer.Size())` to the log fields.

### 25. Missing startup log fields — `internal/app/app.go`

Add to the "initializing application" log: `redis.addr`, `redis.db`, `postgres.host`,
`postgres.port`, `postgres.dbname`, `postgres.sslmode`.

### 26. config.Config() / logging.Logger() stutter — SKIP

Renaming exported functions is a breaking API change for no security benefit. Document
as accepted.

### 27. handler/info.go imports config directly — SKIP for now

Would require passing config values through Handler struct. Low priority, no security
impact.

### 28. Raw upstream error messages — `internal/service/domain.go`

`sanitizeErr` already handles safenet errors. Extend it to strip internal details from
other errors: use the last segment after ": " or a generic "lookup failed" message.

### 29. InsecureSkipVerify — DONE (documented as accepted risk)

### 30. Admin cache invalidation not audit-logged — `internal/httpapi/router.go`

Add `logger.Info("auth cache invalidated", zap.Int("api_key_id", ...))` in the
invalidation handler.

---

## Implementation Order (MEDIUM first)

1. #20, #21 — trivial one-liners
2. #8, #9 — new middleware (security headers, body limit)
3. #10 — safe type assertions in request logger
4. #11 — server-side lookup failure logging
5. #12, #13 — auth failure logging + DB error distinction
6. #14, #15 — Redis close + ping at startup
7. #16 — shared transports
8. #19 — serve tests
9. #22, #23, #24, #25 — request logger improvements + startup log fields
10. #28 — sanitize error messages
11. #30 — admin audit log
12. `make test`, `go build ./...`, `go mod tidy`
