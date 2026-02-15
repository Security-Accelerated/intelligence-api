package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/security-accelerated/intelligence-api/internal/auth"
	"github.com/security-accelerated/intelligence-api/internal/cache"
	"github.com/security-accelerated/intelligence-api/internal/config"
	"github.com/security-accelerated/intelligence-api/internal/handler"
	"github.com/security-accelerated/intelligence-api/internal/logging"
	"github.com/security-accelerated/intelligence-api/internal/middleware"
	"github.com/security-accelerated/intelligence-api/internal/service"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	logger := logging.Logger()
	defer logger.Sync()

	port := config.Config().GetInt("application.port")
	logger.Info("initializing application",
		zap.String("start_time", config.Config().GetString("application.start.time")),
		zap.String("application_name", config.Config().GetString("application.name")),
		zap.String("session_id", config.Config().GetString("application.session.id")),
		zap.String("environment", config.Config().GetString("application.mode")),
		zap.Int("port", port),
		zap.String("host", config.Config().GetString("environment.host")),
		zap.String("golang_version", config.Config().GetString("environment.golang.version")),
		zap.String("architecture", config.Config().GetString("environment.architecture")),
		zap.String("os", config.Config().GetString("environment.os")),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Postgres
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Config().GetString("postgres.host"),
		config.Config().GetInt("postgres.port"),
		config.Config().GetString("postgres.user"),
		config.Config().GetString("postgres.password"),
		config.Config().GetString("postgres.dbname"),
		config.Config().GetString("postgres.sslmode"),
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		logger.Fatal("failed to open postgres connection", zap.Error(err))
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		logger.Fatal("failed to ping postgres", zap.Error(err))
	}
	logger.Info("connected to postgres")

	authRepo := auth.NewPostgresRepository(db)
	authCacheTTL := config.Config().GetDuration("auth.cache_ttl")
	if authCacheTTL == 0 {
		authCacheTTL = 5 * time.Minute
	}
	cachedRepo := auth.NewCachedRepository(authRepo, authCacheTTL)

	if config.Config().GetString("application.mode") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	router.Use(middleware.RequestLogger())

	redisCache := cache.NewRedisCache(
		config.Config().GetString("redis.addr"),
		config.Config().GetString("redis.password"),
		config.Config().GetInt("redis.db"),
	)

	cacheTTL := config.Config().GetDuration("redis.cache_ttl")
	domainService := service.NewDomainService(redisCache, cacheTTL)
	h := handler.New(domainService, version)
	h.RegisterRoutes(router)
	h.RegisterProtectedRoutes(router, middleware.APIKeyAuth(cachedRepo))

	// Admin: auth cache invalidation
	admin := router.Group("/api/v1/admin")
	admin.Use(middleware.APIKeyAuth(cachedRepo), middleware.RequireRoles("admin"))
	admin.POST("/auth/cache/invalidate", func(c *gin.Context) {
		cachedRepo.InvalidateAll()
		c.JSON(http.StatusOK, gin.H{"message": "auth cache invalidated"})
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server started", zap.Int("port", port))
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		logger.Fatal("server error", zap.Error(err))
	case sig := <-shutdown:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed, forcing close", zap.Error(err))
		server.Close()
	}

	logger.Info("application stopped")
}
