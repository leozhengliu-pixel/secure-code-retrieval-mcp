package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"secure-code-retrieval-mcp/internal/app"
	"secure-code-retrieval-mcp/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel.Level()}))
	application, err := app.New(cfg, logger)
	if err != nil {
		logger.Error("bootstrap application", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := application.Run(ctx); err != nil {
		logger.Error("application exited with error", "err", err)
		os.Exit(1)
	}
}
