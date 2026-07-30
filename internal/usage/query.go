package usage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// QueryService retrieves aggregated usage stats from PostgreSQL.
type QueryService struct {
	db *sql.DB
}

// NewQueryService creates a QueryService backed by the given database.
func NewQueryService(db *sql.DB) *QueryService {
	return &QueryService{db: db}
}

// QueryUsage returns aggregated statistics for the given time range. Pass 0 for
// customerID or apiKeyID to skip that filter.
func (qs *QueryService) QueryUsage(customerID, apiKeyID int, since, until time.Time) (*UsageSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	summary := &UsageSummary{
		StatusCodes:    make(map[string]int),
		FeatureUsage:   make(map[string]int),
		RequestsByPath: make(map[string]int),
		PeriodStart:    since,
		PeriodEnd:      until,
	}

	where, args := buildWhere(customerID, apiKeyID, since, until)

	// Aggregated totals. Feature usage counts requests that *asked* for each
	// lookup, independent of whether it was served from cache.
	featureSelects := make([]string, len(LookupColumns))
	for i, name := range LookupColumns {
		featureSelects[i] = fmt.Sprintf("COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0)", name)
	}

	aggQuery := fmt.Sprintf(`SELECT
		COUNT(*),
		COALESCE(SUM(cache_hits), 0),
		COALESCE(SUM(cache_misses), 0),
		COALESCE(AVG(latency_ms), 0),
		COALESCE(SUM(domain_count), 0),
		COALESCE(SUM(ip_count), 0),
		%s
		FROM request_log %s`, strings.Join(featureSelects, ",\n\t\t"), where)

	featureCounts := make([]int, len(LookupColumns))
	dest := []any{
		&summary.TotalRequests,
		&summary.CacheHits,
		&summary.CacheMisses,
		&summary.AvgLatencyMs,
		&summary.TotalDomains,
		&summary.TotalIPs,
	}
	for i := range featureCounts {
		dest = append(dest, &featureCounts[i])
	}

	if err := qs.db.QueryRowContext(ctx, aggQuery, args...).Scan(dest...); err != nil {
		return nil, fmt.Errorf("query usage aggregates: %w", err)
	}

	// Hit rate is per lookup, not per request: a request that serves three
	// cached fields and one live one counts as 3 hits and 1 miss.
	if total := summary.CacheHits + summary.CacheMisses; total > 0 {
		summary.CacheHitRate = float64(summary.CacheHits) / float64(total) * 100
	}
	summary.AvgLatencyMs = float64(int(summary.AvgLatencyMs*100)) / 100 // 2 decimal places

	for i, name := range LookupColumns {
		summary.FeatureUsage[name] = featureCounts[i]
	}

	// Status code breakdown
	scQuery := fmt.Sprintf(`SELECT status_code, COUNT(*) FROM request_log %s GROUP BY status_code`, where)
	rows, err := qs.db.QueryContext(ctx, scQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query status codes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var code, count int
		if err := rows.Scan(&code, &count); err != nil {
			return nil, fmt.Errorf("scan status code row: %w", err)
		}
		summary.StatusCodes[fmt.Sprintf("%d", code)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status codes: %w", err)
	}

	// Requests by path
	pathQuery := fmt.Sprintf(`SELECT path, COUNT(*) FROM request_log %s GROUP BY path ORDER BY COUNT(*) DESC LIMIT 50`, where)
	rows2, err := qs.db.QueryContext(ctx, pathQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query paths: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var path string
		var count int
		if err := rows2.Scan(&path, &count); err != nil {
			return nil, fmt.Errorf("scan path row: %w", err)
		}
		summary.RequestsByPath[path] = count
	}
	if err := rows2.Err(); err != nil {
		return nil, fmt.Errorf("iterate paths: %w", err)
	}

	return summary, nil
}

func buildWhere(customerID, apiKeyID int, since, until time.Time) (string, []any) {
	clauses := []string{"created_at >= $1", "created_at < $2"}
	args := []any{since, until}
	idx := 3

	if customerID > 0 {
		clauses = append(clauses, fmt.Sprintf("customer_id = $%d", idx))
		args = append(args, customerID)
		idx++
	}
	if apiKeyID > 0 {
		clauses = append(clauses, fmt.Sprintf("api_key_id = $%d", idx))
		args = append(args, apiKeyID)
	}

	return "WHERE " + strings.Join(clauses, " AND "), args
}
