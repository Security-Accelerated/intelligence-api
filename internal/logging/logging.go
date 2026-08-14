package logging

import (
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/security-accelerated/intelligence-api/internal/config"
	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var appLogger *zap.Logger

const (
	// Environments.
	production = "production"
	docker     = "docker"
)

func inflateLogger(logger *zap.Logger) *zap.Logger {
	return logger.With(
		zap.String("application_name", config.Config().GetString("application.name")),
		zap.String("session_id", config.Config().GetString("application.session.id")),
		zap.String("host", config.Config().GetString("environment.host")),
	)
}

func productionLogger() (*zap.Logger, error) {
	// Not named `config`: that is the imported package this file calls elsewhere
	// (config.Config()), and shadowing it makes the package unreachable here.
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig = ecszap.ECSCompatibleEncoderConfig(cfg.EncoderConfig)

	logger, err := cfg.Build(ecszap.WrapCoreOption(), zap.AddCaller())
	if err != nil {
		return nil, err
	}

	return inflateLogger(logger), nil
}

func logger(env string) (*zap.Logger, error) {
	switch strings.ToLower(env) {
	case docker, production:
		return productionLogger()
	default:
		return zap.NewDevelopment(zap.AddStacktrace(zapcore.ErrorLevel))
	}
}

func init() {
	env := config.Config().GetString("application.mode")

	newLogger, err := logger(env)
	if err != nil {
		panic(err)
	}

	appLogger = newLogger
}

func Logger() *zap.Logger {
	return appLogger
}

// Sync flushes buffered log entries while ignoring the benign sync errors that
// stdout/stderr can return on some platforms.
func Sync(logger *zap.Logger) error {
	if logger == nil {
		return nil
	}
	if err := logger.Sync(); err != nil && !ignorableSyncError(err) {
		return err
	}
	return nil
}

func ignorableSyncError(err error) bool {
	return errors.Is(err, os.ErrInvalid) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTTY)
}
