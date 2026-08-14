package main

import (
	"os"

	"github.com/security-accelerated/intelligence-api/internal/app"
	"github.com/security-accelerated/intelligence-api/internal/logging"
)

var version = "dev"

// main does nothing but translate run's result into an exit code. os.Exit skips
// deferred functions, so anything that must run on the way out — flushing the
// log buffer, in particular — has to live in a function that returns normally.
// Previously the flush was written twice, once deferred and once by hand before
// os.Exit, which is the same fix spelled in a way that has to be remembered
// each time a new exit path is added.
func main() {
	os.Exit(run())
}

// run owns the process lifecycle and returns the intended exit code.
func run() int {
	logger := logging.Logger()
	defer func() {
		if err := logging.Sync(logger); err != nil {
			_, _ = os.Stderr.WriteString("logger sync failed: " + err.Error() + "\n")
		}
	}()

	if err := app.Run(logger, version); err != nil {
		logger.Error(err.Error())
		return 1
	}
	return 0
}
