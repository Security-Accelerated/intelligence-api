package config

import (
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
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

	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		config.Set("environment.kernel", charsToString(uname.Release[:]))
	}

	// defaults (overridden by config file, then env vars)
	config.SetDefault("application.port", 8080)
	config.SetDefault("redis.cache_ttl", "60m")
	config.SetDefault("auth.cache_ttl", "5m")
	config.SetDefault("screenshot.timeout", "15s")
	config.SetDefault("typosquatting.timeout", "30s")
	config.SetDefault("typosquatting.max_permutations", 500)
	config.SetDefault("typosquatting.concurrency", 20)
	config.SetDefault("domain.max_domains.basic", 5)
	config.SetDefault("domain.max_domains.premium", 20)
	config.SetDefault("typosquatting.max_domains.basic", 3)
	config.SetDefault("typosquatting.max_domains.premium", 5)
	config.SetDefault("subdomain.timeout", "30s")
	config.SetDefault("subdomain.max_results", 500)
	config.SetDefault("subdomain.concurrency", 20)
	config.SetDefault("subdomain.max_domains.basic", 3)
	config.SetDefault("subdomain.max_domains.premium", 5)
	config.SetDefault("rate_limit.basic", 30)
	config.SetDefault("rate_limit.premium", 120)
	config.SetDefault("postgres.sslmode", "require")

	// allow env vars to override config: POSTGRES_HOST → postgres.host
	config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	config.AutomaticEnv()

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

func charsToString(ca []int8) string {
	b := make([]byte, 0, len(ca))
	for _, c := range ca {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
