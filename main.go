package main

import (
	"log/slog"
	"net/http"
	"os"
)

// main wires configuration, logging, HTTP routes, and then starts the iprememberme server.
func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	srv := newServer(cfg, newStore(cfg.Duration, cfg.MaxIPsPerUser), logger)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	logger.Info("starting server", "addr", cfg.ListenAddr, "duration", cfg.Duration.String(), "maxIPsPerUser", cfg.MaxIPsPerUser)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.logging(mux)); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}
