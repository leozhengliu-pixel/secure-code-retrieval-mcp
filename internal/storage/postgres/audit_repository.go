package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type AuditRepository struct {
	db          *sql.DB
	logger      *slog.Logger
	schemaOnce  sync.Once
	schemaError error
}

func NewAuditRepository(cfg config.DatabaseConfig, logger *slog.Logger) (*AuditRepository, error) {
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, err
	}
	return &AuditRepository{db: db, logger: logger}, nil
}

func (r *AuditRepository) EnsureSchema(ctx context.Context) error {
	r.schemaOnce.Do(func() {
		_, r.schemaError = r.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS audit_requests (
  audit_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  caller_principal TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_host TEXT NOT NULL,
  query_text TEXT NOT NULL,
  filters_json JSONB NOT NULL,
  policy_profile TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_decisions (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT NOT NULL,
  audit_id TEXT NOT NULL,
  repository TEXT NOT NULL,
  file_path TEXT NOT NULL,
  decision TEXT NOT NULL,
  matched_rules JSONB NOT NULL,
  model_invoked BOOLEAN NOT NULL,
  release_mode TEXT NOT NULL,
  suppression_reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_deliveries (
  audit_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  snippet_count INT NOT NULL,
  response_bytes INT NOT NULL,
  connector_stats JSONB NOT NULL,
  latency_millis BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);`)
	})
	return r.schemaError
}

func (r *AuditRepository) CreateRequest(ctx context.Context, auditID string, record domain.AuditRequestRecord) error {
	filtersJSON, _ := json.Marshal(record.Filters)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_requests (audit_id, request_id, tenant_id, caller_principal, source_type, source_host, query_text, filters_json, policy_profile, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, auditID, record.RequestID, record.TenantID, record.CallerPrincipal, record.SourceType, record.SourceHost, record.QueryText, filtersJSON, record.PolicyProfile, record.CreatedAt)
	return err
}

func (r *AuditRepository) CreateDecision(ctx context.Context, record domain.AuditDecisionRecord) error {
	rulesJSON, _ := json.Marshal(record.MatchedRules)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_decisions (request_id, audit_id, repository, file_path, decision, matched_rules, model_invoked, release_mode, suppression_reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, record.RequestID, record.AuditID, record.Repository, record.FilePath, record.Decision, rulesJSON, record.ModelInvoked, record.ReleaseMode, record.SuppressionReason, record.CreatedAt)
	return err
}

func (r *AuditRepository) CreateDelivery(ctx context.Context, record domain.AuditDeliveryRecord) error {
	statsJSON, _ := json.Marshal(record.ConnectorStats)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_deliveries (audit_id, request_id, snippet_count, response_bytes, connector_stats, latency_millis, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (audit_id) DO UPDATE SET snippet_count=EXCLUDED.snippet_count, response_bytes=EXCLUDED.response_bytes, connector_stats=EXCLUDED.connector_stats, latency_millis=EXCLUDED.latency_millis, created_at=EXCLUDED.created_at`, record.AuditID, record.RequestID, record.SnippetCount, record.ResponseBytes, statsJSON, record.LatencyMillis, record.CreatedAt)
	return err
}

func (r *AuditRepository) GetBundle(ctx context.Context, requestID string) (domain.AuditBundle, error) {
	var bundle domain.AuditBundle
	var sourceType string
	var filtersJSON []byte
	var auditID string
	row := r.db.QueryRowContext(ctx, `SELECT request_id, tenant_id, caller_principal, source_type, source_host, query_text, filters_json, policy_profile, created_at, audit_id FROM audit_requests WHERE request_id = $1`, requestID)
	if err := row.Scan(&bundle.Request.RequestID, &bundle.Request.TenantID, &bundle.Request.CallerPrincipal, &sourceType, &bundle.Request.SourceHost, &bundle.Request.QueryText, &filtersJSON, &bundle.Request.PolicyProfile, &bundle.Request.CreatedAt, &auditID); err != nil {
		return domain.AuditBundle{}, err
	}
	bundle.Request.SourceType = domain.SourceType(sourceType)
	_ = json.Unmarshal(filtersJSON, &bundle.Request.Filters)

	rows, err := r.db.QueryContext(ctx, `SELECT request_id, audit_id, repository, file_path, decision, matched_rules, model_invoked, release_mode, suppression_reason, created_at FROM audit_decisions WHERE request_id = $1 ORDER BY id ASC`, requestID)
	if err != nil {
		return domain.AuditBundle{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var record domain.AuditDecisionRecord
		var rulesJSON []byte
		var decision string
		if err := rows.Scan(&record.RequestID, &record.AuditID, &record.Repository, &record.FilePath, &decision, &rulesJSON, &record.ModelInvoked, &record.ReleaseMode, &record.SuppressionReason, &record.CreatedAt); err != nil {
			return domain.AuditBundle{}, err
		}
		record.Decision = domain.DecisionAction(decision)
		_ = json.Unmarshal(rulesJSON, &record.MatchedRules)
		bundle.Decisions = append(bundle.Decisions, record)
	}

	var statsJSON []byte
	if err := r.db.QueryRowContext(ctx, `SELECT request_id, audit_id, snippet_count, response_bytes, connector_stats, latency_millis, created_at FROM audit_deliveries WHERE audit_id = $1`, auditID).Scan(&bundle.Delivery.RequestID, &bundle.Delivery.AuditID, &bundle.Delivery.SnippetCount, &bundle.Delivery.ResponseBytes, &statsJSON, &bundle.Delivery.LatencyMillis, &bundle.Delivery.CreatedAt); err != nil {
		return domain.AuditBundle{}, err
	}
	_ = json.Unmarshal(statsJSON, &bundle.Delivery.ConnectorStats)
	return bundle, nil
}
