package handler

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// systemWithUptime embeds SystemStatus and adds the computed uptime field.
type systemWithUptime struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Mode            string    `json:"mode"`
	SessionID       string    `json:"session_id"`
	StartTime       time.Time `json:"start_time"`
	Uptime          string    `json:"uptime"`
	Host            string    `json:"host"`
	OS              string    `json:"os"`
	Kernel          string    `json:"kernel"`
	Architecture    string    `json:"architecture"`
	GoVersion       string    `json:"golang_version"`
	GinMode         string    `json:"gin_mode"`
	Port            int       `json:"port"`
	ReadTimeout     string    `json:"read_timeout"`
	WriteTimeout    string    `json:"write_timeout"`
	IdleTimeout     string    `json:"idle_timeout"`
	ShutdownTimeout string    `json:"shutdown_timeout"`
	BodyLimit       int       `json:"body_limit"`
}

type runtimeStats struct {
	Goroutines  int     `json:"goroutines"`
	HeapAllocMB float64 `json:"heap_alloc_mb"`
	HeapInuseMB float64 `json:"heap_inuse_mb"`
	SysMB       float64 `json:"sys_mb"`
	NumGC       uint32  `json:"num_gc"`
}

type poolStats struct {
	OpenConnections int    `json:"open_connections"`
	InUse           int    `json:"in_use"`
	Idle            int    `json:"idle"`
	WaitCount       int64  `json:"wait_count"`
	WaitDuration    string `json:"wait_duration"`
}

type cacheStats struct {
	Addr          string            `json:"addr"`
	DB            int               `json:"db"`
	DefaultTTL    string            `json:"default_ttl"`
	LookupTTLs    map[string]string `json:"lookup_ttls,omitempty"`
	AuthCacheTTL  string            `json:"auth_cache_ttl"`
	PingMs        *float64          `json:"ping_ms,omitempty"`
	KeyCount      *int64            `json:"key_count,omitempty"`
	MemoryUsed    string            `json:"memory_used,omitempty"`
	AuthCacheSize *int              `json:"auth_cache_size,omitempty"`
}

func (h *Handler) Info(c *gin.Context) {
	if h.status == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "status not configured"})
		return
	}

	s := h.status

	// System — static snapshot + computed uptime
	sys := systemWithUptime{
		Name:            s.System.Name,
		Version:         s.System.Version,
		Mode:            s.System.Mode,
		SessionID:       s.System.SessionID,
		StartTime:       s.System.StartTime,
		Uptime:          time.Since(s.System.StartTime).Truncate(time.Second).String(),
		Host:            s.System.Host,
		OS:              s.System.OS,
		Kernel:          s.System.Kernel,
		Architecture:    s.System.Architecture,
		GoVersion:       s.System.GoVersion,
		GinMode:         s.System.GinMode,
		Port:            s.System.Port,
		ReadTimeout:     s.System.ReadTimeout,
		WriteTimeout:    s.System.WriteTimeout,
		IdleTimeout:     s.System.IdleTimeout,
		ShutdownTimeout: s.System.ShutdownTimeout,
		BodyLimit:       s.System.BodyLimit,
	}

	resp := gin.H{
		"system":   sys,
		"database": s.Database,
		"lookups":  s.Lookups,
		"services": s.GetServices(),
	}

	// Runtime stats
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	resp["runtime"] = runtimeStats{
		Goroutines:  runtime.NumGoroutine(),
		HeapAllocMB: float64(mem.HeapAlloc) / 1024 / 1024,
		HeapInuseMB: float64(mem.HeapInuse) / 1024 / 1024,
		SysMB:       float64(mem.Sys) / 1024 / 1024,
		NumGC:       mem.NumGC,
	}

	// Database pool stats
	if h.db != nil {
		dbStats := h.db.Stats()
		resp["postgres_pool"] = poolStats{
			OpenConnections: dbStats.OpenConnections,
			InUse:           dbStats.InUse,
			Idle:            dbStats.Idle,
			WaitCount:       dbStats.WaitCount,
			WaitDuration:    dbStats.WaitDuration.String(),
		}
	}

	// Cache — static config + live data
	cs := cacheStats{
		Addr:         s.Cache.Addr,
		DB:           s.Cache.DB,
		DefaultTTL:   s.Cache.DefaultTTL,
		LookupTTLs:   s.Cache.LookupTTLs,
		AuthCacheTTL: s.Cache.AuthCacheTTL,
	}

	if h.redisCache != nil {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		client := h.redisCache.Client()

		pingStart := time.Now()
		if err := client.Ping(ctx).Err(); err == nil {
			ms := float64(time.Since(pingStart).Microseconds()) / 1000.0
			cs.PingMs = &ms
		}

		if keyCount, err := client.DBSize(ctx).Result(); err == nil {
			cs.KeyCount = &keyCount
		}

		if info, err := client.Info(ctx, "memory").Result(); err == nil {
			for _, line := range strings.Split(info, "\r\n") {
				if v, ok := strings.CutPrefix(line, "used_memory_human:"); ok {
					cs.MemoryUsed = v
					break
				}
			}
		}
	}

	if h.authCacheStats != nil {
		size := h.authCacheStats.Size()
		cs.AuthCacheSize = &size
	}

	resp["cache"] = cs

	c.JSON(http.StatusOK, resp)
}
