package config

import (
	"log"
	"os"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var config *viper.Viper

const appName = "intelligence-api"

func init() {
	config = viper.New()

	// setup config sources
	config.SetConfigType("yaml")
	config.SetConfigName(appName)
	config.AddConfigPath("../../config/")
	config.AddConfigPath("../config/")
	config.AddConfigPath("config/")
	config.AddConfigPath("/etc/" + appName + "/")
	config.AddConfigPath("/etc/security-accelerated/")

	// application
	config.Set("application.start.time", time.Now().UTC())
	config.Set("application.name", appName)
	config.Set("application.session.id", uuid.New().String())

	// environment information
	host, err := os.Hostname()
	if err != nil {
		log.Fatalf("error generating hostname, %s", err)
	}
	config.Set("environment.host", host)
	config.Set("environment.golang.version", runtime.Version())
	config.Set("environment.architecture", runtime.GOARCH)
	config.Set("environment.os", runtime.GOOS)

	// pull from env if not set in config file
	viper.AutomaticEnv()

	// read in config
	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("no config file found")
		} else {
			log.Fatalf("error reading config file %s.yaml: %s", appName, err)
		}
	}
}

func Config() *viper.Viper {
	return config
}
