package main

import (
	"os"

	"github.com/security-accelerated/intelligence-api/internal/app"
	"github.com/security-accelerated/intelligence-api/internal/logging"
)

var version = "dev"

func main() {
	logger := logging.Logger()
	defer logger.Sync()

	if err := app.Run(logger, version); err != nil {
		logger.Error(err.Error())
		logger.Sync()
		os.Exit(1)
	}
}
