package main

import (
	"context"
	"log/slog"
	"os"

	"secure-code-retrieval-mcp/internal/config"
	postgresstore "secure-code-retrieval-mcp/internal/storage/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	repository, err := postgresstore.NewAuditRepository(cfg.Database, slog.Default())
	if err != nil {
		slog.Error("open database", "err", err)
		os.Exit(1)
	}
	if err := postgresstore.NewMigrator(repository.DB()).Apply(context.Background()); err != nil {
		slog.Error("apply migrations", "err", err)
		os.Exit(1)
	}
}
