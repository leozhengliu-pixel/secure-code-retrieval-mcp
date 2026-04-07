package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"

	_ "github.com/jackc/pgx/v5/stdlib"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type AuditRepository struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewAuditRepository(cfg config.DatabaseConfig, logger *slog.Logger) (*AuditRepository, error) {
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, err
	}
	return &AuditRepository{db: db, logger: logger}, nil
}

func (r *AuditRepository) DB() *sql.DB {
	return r.db
}

func (r *AuditRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *AuditRepository) CreateRequest(ctx context.Context, auditID string, record domain.AuditRequestRecord) error {
	filtersJSON, _ := json.Marshal(record.Filters)
	rolesJSON, _ := json.Marshal(record.CallerRoles)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_requests (audit_id, request_id, caller_principal, caller_roles_json, source_type, source_host, query_text, filters_json, policy_profile, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, auditID, record.RequestID, record.CallerPrincipal, rolesJSON, record.SourceType, record.SourceHost, record.QueryText, filtersJSON, record.PolicyProfile, record.CreatedAt)
	return err
}

func (r *AuditRepository) CreateDecision(ctx context.Context, record domain.AuditDecisionRecord) error {
	rulesJSON, _ := json.Marshal(record.MatchedRules)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_decisions (request_id, audit_id, evidence_id, repository, file_path, line_start, line_end, decision, matched_rules, model_invoked, release_mode, suppression_reason, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, record.RequestID, record.AuditID, record.EvidenceID, record.Repository, record.FilePath, record.LineStart, record.LineEnd, record.Decision, rulesJSON, record.ModelInvoked, record.ReleaseMode, record.SuppressionReason, record.CreatedAt)
	return err
}

func (r *AuditRepository) CreateDelivery(ctx context.Context, record domain.AuditDeliveryRecord) error {
	statsJSON, _ := json.Marshal(record.ConnectorStats)
	citationJSON, _ := json.Marshal(record.SummaryCitationIDs)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_deliveries (audit_id, request_id, snippet_count, raw_hit_count, evidence_count, suppressed_count, response_bytes, connector_stats, latency_millis, results_truncated, suppressed_due_to_budget, remaining_hits_estimate, summary_generated, summary_citation_ids, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT (audit_id) DO UPDATE SET snippet_count=EXCLUDED.snippet_count, raw_hit_count=EXCLUDED.raw_hit_count, evidence_count=EXCLUDED.evidence_count, suppressed_count=EXCLUDED.suppressed_count, response_bytes=EXCLUDED.response_bytes, connector_stats=EXCLUDED.connector_stats, latency_millis=EXCLUDED.latency_millis, results_truncated=EXCLUDED.results_truncated, suppressed_due_to_budget=EXCLUDED.suppressed_due_to_budget, remaining_hits_estimate=EXCLUDED.remaining_hits_estimate, summary_generated=EXCLUDED.summary_generated, summary_citation_ids=EXCLUDED.summary_citation_ids, created_at=EXCLUDED.created_at`, record.AuditID, record.RequestID, record.SnippetCount, record.RawHitCount, record.EvidenceCount, record.SuppressedCount, record.ResponseBytes, statsJSON, record.LatencyMillis, record.ResultsTruncated, record.SuppressedDueToBudget, record.RemainingHitsEstimate, record.SummaryGenerated, citationJSON, record.CreatedAt)
	return err
}

func (r *AuditRepository) GetBundle(ctx context.Context, requestID string) (domain.AuditBundle, error) {
	var bundle domain.AuditBundle
	var sourceType string
	var filtersJSON []byte
	var rolesJSON []byte
	var auditID string
	row := r.db.QueryRowContext(ctx, `SELECT request_id, caller_principal, caller_roles_json, source_type, source_host, query_text, filters_json, policy_profile, created_at, audit_id FROM audit_requests WHERE request_id = $1`, requestID)
	if err := row.Scan(&bundle.Request.RequestID, &bundle.Request.CallerPrincipal, &rolesJSON, &sourceType, &bundle.Request.SourceHost, &bundle.Request.QueryText, &filtersJSON, &bundle.Request.PolicyProfile, &bundle.Request.CreatedAt, &auditID); err != nil {
		return domain.AuditBundle{}, err
	}
	bundle.Request.SourceType = domain.SourceType(sourceType)
	_ = json.Unmarshal(filtersJSON, &bundle.Request.Filters)
	_ = json.Unmarshal(rolesJSON, &bundle.Request.CallerRoles)

	rows, err := r.db.QueryContext(ctx, `SELECT request_id, audit_id, evidence_id, repository, file_path, line_start, line_end, decision, matched_rules, model_invoked, release_mode, suppression_reason, created_at FROM audit_decisions WHERE request_id = $1 ORDER BY id ASC`, requestID)
	if err != nil {
		return domain.AuditBundle{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var record domain.AuditDecisionRecord
		var rulesJSON []byte
		var decision string
		if err := rows.Scan(&record.RequestID, &record.AuditID, &record.EvidenceID, &record.Repository, &record.FilePath, &record.LineStart, &record.LineEnd, &decision, &rulesJSON, &record.ModelInvoked, &record.ReleaseMode, &record.SuppressionReason, &record.CreatedAt); err != nil {
			return domain.AuditBundle{}, err
		}
		record.Decision = domain.DecisionAction(decision)
		_ = json.Unmarshal(rulesJSON, &record.MatchedRules)
		bundle.Decisions = append(bundle.Decisions, record)
	}

	var statsJSON []byte
	var citationJSON []byte
	if err := r.db.QueryRowContext(ctx, `SELECT request_id, audit_id, snippet_count, raw_hit_count, evidence_count, suppressed_count, response_bytes, connector_stats, latency_millis, results_truncated, suppressed_due_to_budget, remaining_hits_estimate, summary_generated, summary_citation_ids, created_at FROM audit_deliveries WHERE audit_id = $1`, auditID).Scan(&bundle.Delivery.RequestID, &bundle.Delivery.AuditID, &bundle.Delivery.SnippetCount, &bundle.Delivery.RawHitCount, &bundle.Delivery.EvidenceCount, &bundle.Delivery.SuppressedCount, &bundle.Delivery.ResponseBytes, &statsJSON, &bundle.Delivery.LatencyMillis, &bundle.Delivery.ResultsTruncated, &bundle.Delivery.SuppressedDueToBudget, &bundle.Delivery.RemainingHitsEstimate, &bundle.Delivery.SummaryGenerated, &citationJSON, &bundle.Delivery.CreatedAt); err != nil {
		return domain.AuditBundle{}, err
	}
	_ = json.Unmarshal(statsJSON, &bundle.Delivery.ConnectorStats)
	_ = json.Unmarshal(citationJSON, &bundle.Delivery.SummaryCitationIDs)
	return bundle, nil
}
