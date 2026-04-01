package main

import (
	"os"

	"github.com/security-accelerated/intelligence-api/internal/app"
	"github.com/security-accelerated/intelligence-api/internal/logging"
)

var version = "dev"

func main() {
	logger := logging.Logger()
	defer func() {
		if err := logging.Sync(logger); err != nil {
			_, _ = os.Stderr.WriteString("logger sync failed: " + err.Error() + "\n")
		}
	}()

	if err := app.Run(logger, version); err != nil {
		logger.Error(err.Error())
		if syncErr := logging.Sync(logger); syncErr != nil {
			_, _ = os.Stderr.WriteString("logger sync failed: " + syncErr.Error() + "\n")
		}
		os.Exit(1)
	}
}
