package main

import (
	"context"
	"log/slog"
	"os"

	"secure-code-retrieval-mcp/internal/config"
	postgresstore "secure-code-retrieval-mcp/internal/storage/postgres"
	sqlitestore "secure-code-retrieval-mcp/internal/storage/sqlite"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if err := applyMigrations(cfg); err != nil {
		slog.Error("apply migrations", "err", err)
		os.Exit(1)
	}
}

func applyMigrations(cfg config.Config) error {
	if cfg.Database.DSN != "" {
		repository, err := postgresstore.NewAuditRepository(cfg.Database, slog.Default())
		if err != nil {
			return err
		}
		return postgresstore.NewMigrator(repository.DB()).Apply(context.Background())
	}
	repository, err := sqlitestore.NewAuditRepository(cfg.Database, slog.Default())
	if err != nil {
		return err
	}
	return sqlitestore.NewMigrator(repository.DB()).Apply(context.Background())
}
