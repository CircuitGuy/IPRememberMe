package main

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// config captures every runtime knob for the iprememberme service.
// Values come from environment variables so container users can tweak behavior without rebuilding.
type config struct {
	SharedSecret         string
	Duration             time.Duration
	MaxIPsPerUser        int
	ListenAddr           string
	LogLevel             slog.Level
	AutheliaURL          string
	InsecureTLS          bool
	AutheliaVerify       bool
	AutheliaAllowHeader  bool
	AutheliaToggleHeader string
	AutheliaTimeout      time.Duration
	CookieDomain         string
}

// loadConfig reads environment variables, applies defaults, and emits the config struct.
// Keeping this logic in one place avoids sprinkling env parsing around the codebase.
func loadConfig() config {
	duration := time.Duration(getenvInt("ALLOW_DURATION_HOURS", 24)) * time.Hour
	timeout := time.Duration(getenvInt("AUTHELIA_TIMEOUT_SECONDS", 5)) * time.Second
	logLevel := parseLogLevel(getenv("LOG_LEVEL", "info"))
	return config{
		SharedSecret:         os.Getenv("SHARED_SECRET"),
		Duration:             duration,
		MaxIPsPerUser:        getenvInt("MAX_IPS_PER_USER", 3),
		ListenAddr:           getenv("LISTEN_ADDR", ":8080"),
		LogLevel:             logLevel,
		AutheliaURL:          os.Getenv("AUTHELIA_URL"),
		InsecureTLS:          getenvBool("AUTHELIA_INSECURE_SKIP_VERIFY", false),
		AutheliaVerify:       getenvBool("AUTHELIA_VERIFY", true),
		AutheliaAllowHeader:  getenvBool("AUTHELIA_ALLOW_HEADER_TOGGLE", false),
		AutheliaToggleHeader: getenv("AUTHELIA_TOGGLE_HEADER", "X-IPREMEMBER-AUTHELIA"),
		AutheliaTimeout:      timeout,
		CookieDomain:         os.Getenv("COOKIE_DOMAIN"),
	}
}

func getenv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func getenvBool(key string, def bool) bool {
	val := strings.ToLower(os.Getenv(key))
	if val == "" {
		return def
	}
	return val == "1" || val == "true" || val == "yes" || val == "on"
}

func getenvInt(key string, def int) int {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return n
}

func parseLogLevel(raw string) slog.Level {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
