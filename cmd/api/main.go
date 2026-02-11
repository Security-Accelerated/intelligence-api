package main

import (
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/config"
	"github.com/securityaccelerateddevelopment/intelligence-api/internal/logging"
	"go.uber.org/zap"
)

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
}
