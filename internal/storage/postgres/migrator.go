package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Migrator struct {
	db *sql.DB
}

func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

func (m *Migrator) RequiredVersion(ctx context.Context) (int64, error) {
	versions, err := m.availableVersions()
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, nil
	}
	return versions[len(versions)-1], nil
}

func (m *Migrator) CurrentVersion(ctx context.Context) (int64, error) {
	if _, err := m.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)`); err != nil {
		return 0, err
	}
	var version sql.NullInt64
	if err := m.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, err
	}
	if !version.Valid {
		return 0, nil
	}
	return version.Int64, nil
}

func (m *Migrator) Apply(ctx context.Context) error {
	versions, err := m.availableVersions()
	if err != nil {
		return err
	}
	current, err := m.CurrentVersion(ctx)
	if err != nil {
		return err
	}
	for _, version := range versions {
		if version <= current {
			continue
		}
		if err := m.applyVersion(ctx, version); err != nil {
			return err
		}
	}
	return nil
}

func (m *Migrator) applyVersion(ctx context.Context, version int64) error {
	body, err := migrationFiles.ReadFile(fmt.Sprintf("migrations/%04d_audit.sql", version))
	if err != nil {
		return err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`, version, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Migrator) CheckReady(ctx context.Context) error {
	current, err := m.CurrentVersion(ctx)
	if err != nil {
		return err
	}
	required, err := m.RequiredVersion(ctx)
	if err != nil {
		return err
	}
	if current < required {
		return fmt.Errorf("%w: database schema version %d is below required %d", sql.ErrNoRows, current, required)
	}
	return nil
}

func (m *Migrator) availableVersions() ([]int64, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	versions := make([]int64, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		prefix := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
		number := strings.SplitN(prefix, "_", 2)[0]
		version, err := strconv.ParseInt(number, 10, 64)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}
