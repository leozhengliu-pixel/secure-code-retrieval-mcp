package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type AuditRepository struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewAuditRepository(cfg config.DatabaseConfig, logger *slog.Logger) (*AuditRepository, error) {
	path := cfg.SQLitePath
	if path == "" {
		path = "var/secure-code-retrieval.db"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
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
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_requests (audit_id, request_id, caller_principal, caller_roles_json, source_type, source_host, query_text, filters_json, policy_profile, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, auditID, record.RequestID, record.CallerPrincipal, string(rolesJSON), record.SourceType, record.SourceHost, record.QueryText, string(filtersJSON), record.PolicyProfile, formatTimestamp(record.CreatedAt))
	return err
}

func (r *AuditRepository) CreateDecision(ctx context.Context, record domain.AuditDecisionRecord) error {
	rulesJSON, _ := json.Marshal(record.MatchedRules)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_decisions (request_id, audit_id, evidence_id, repository, file_path, line_start, line_end, decision, matched_rules, model_invoked, release_mode, suppression_reason, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.RequestID, record.AuditID, record.EvidenceID, record.Repository, record.FilePath, record.LineStart, record.LineEnd, record.Decision, string(rulesJSON), record.ModelInvoked, record.ReleaseMode, record.SuppressionReason, formatTimestamp(record.CreatedAt))
	return err
}

func (r *AuditRepository) CreateDelivery(ctx context.Context, record domain.AuditDeliveryRecord) error {
	statsJSON, _ := json.Marshal(record.ConnectorStats)
	citationJSON, _ := json.Marshal(record.SummaryCitationIDs)
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_deliveries (audit_id, request_id, snippet_count, raw_hit_count, evidence_count, suppressed_count, response_bytes, connector_stats, latency_millis, results_truncated, suppressed_due_to_budget, remaining_hits_estimate, summary_generated, summary_citation_ids, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(audit_id) DO UPDATE SET snippet_count=excluded.snippet_count, raw_hit_count=excluded.raw_hit_count, evidence_count=excluded.evidence_count, suppressed_count=excluded.suppressed_count, response_bytes=excluded.response_bytes, connector_stats=excluded.connector_stats, latency_millis=excluded.latency_millis, results_truncated=excluded.results_truncated, suppressed_due_to_budget=excluded.suppressed_due_to_budget, remaining_hits_estimate=excluded.remaining_hits_estimate, summary_generated=excluded.summary_generated, summary_citation_ids=excluded.summary_citation_ids, created_at=excluded.created_at`, record.AuditID, record.RequestID, record.SnippetCount, record.RawHitCount, record.EvidenceCount, record.SuppressedCount, record.ResponseBytes, string(statsJSON), record.LatencyMillis, record.ResultsTruncated, record.SuppressedDueToBudget, record.RemainingHitsEstimate, record.SummaryGenerated, string(citationJSON), formatTimestamp(record.CreatedAt))
	return err
}

func (r *AuditRepository) GetBundle(ctx context.Context, requestID string) (domain.AuditBundle, error) {
	var bundle domain.AuditBundle
	var sourceType string
	var filtersJSON string
	var rolesJSON string
	var createdAt string
	var auditID string
	row := r.db.QueryRowContext(ctx, `SELECT request_id, caller_principal, caller_roles_json, source_type, source_host, query_text, filters_json, policy_profile, created_at, audit_id FROM audit_requests WHERE request_id = ?`, requestID)
	if err := row.Scan(&bundle.Request.RequestID, &bundle.Request.CallerPrincipal, &rolesJSON, &sourceType, &bundle.Request.SourceHost, &bundle.Request.QueryText, &filtersJSON, &bundle.Request.PolicyProfile, &createdAt, &auditID); err != nil {
		return domain.AuditBundle{}, err
	}
	parsedRequestTime, err := parseTimestamp(createdAt)
	if err != nil {
		return domain.AuditBundle{}, err
	}
	bundle.Request.CreatedAt = parsedRequestTime
	bundle.Request.SourceType = domain.SourceType(sourceType)
	_ = json.Unmarshal([]byte(filtersJSON), &bundle.Request.Filters)
	_ = json.Unmarshal([]byte(rolesJSON), &bundle.Request.CallerRoles)

	rows, err := r.db.QueryContext(ctx, `SELECT request_id, audit_id, evidence_id, repository, file_path, line_start, line_end, decision, matched_rules, model_invoked, release_mode, suppression_reason, created_at FROM audit_decisions WHERE request_id = ? ORDER BY id ASC`, requestID)
	if err != nil {
		return domain.AuditBundle{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var record domain.AuditDecisionRecord
		var rulesJSON string
		var decision string
		var decisionCreatedAt string
		if err := rows.Scan(&record.RequestID, &record.AuditID, &record.EvidenceID, &record.Repository, &record.FilePath, &record.LineStart, &record.LineEnd, &decision, &rulesJSON, &record.ModelInvoked, &record.ReleaseMode, &record.SuppressionReason, &decisionCreatedAt); err != nil {
			return domain.AuditBundle{}, err
		}
		record.CreatedAt, err = parseTimestamp(decisionCreatedAt)
		if err != nil {
			return domain.AuditBundle{}, err
		}
		record.Decision = domain.DecisionAction(decision)
		_ = json.Unmarshal([]byte(rulesJSON), &record.MatchedRules)
		bundle.Decisions = append(bundle.Decisions, record)
	}

	var statsJSON string
	var citationJSON string
	var deliveryCreatedAt string
	if err := r.db.QueryRowContext(ctx, `SELECT request_id, audit_id, snippet_count, raw_hit_count, evidence_count, suppressed_count, response_bytes, connector_stats, latency_millis, results_truncated, suppressed_due_to_budget, remaining_hits_estimate, summary_generated, summary_citation_ids, created_at FROM audit_deliveries WHERE audit_id = ?`, auditID).Scan(&bundle.Delivery.RequestID, &bundle.Delivery.AuditID, &bundle.Delivery.SnippetCount, &bundle.Delivery.RawHitCount, &bundle.Delivery.EvidenceCount, &bundle.Delivery.SuppressedCount, &bundle.Delivery.ResponseBytes, &statsJSON, &bundle.Delivery.LatencyMillis, &bundle.Delivery.ResultsTruncated, &bundle.Delivery.SuppressedDueToBudget, &bundle.Delivery.RemainingHitsEstimate, &bundle.Delivery.SummaryGenerated, &citationJSON, &deliveryCreatedAt); err != nil {
		return domain.AuditBundle{}, err
	}
	bundle.Delivery.CreatedAt, err = parseTimestamp(deliveryCreatedAt)
	if err != nil {
		return domain.AuditBundle{}, err
	}
	_ = json.Unmarshal([]byte(statsJSON), &bundle.Delivery.ConnectorStats)
	_ = json.Unmarshal([]byte(citationJSON), &bundle.Delivery.SummaryCitationIDs)
	return bundle, nil
}

func formatTimestamp(ts time.Time) string {
	return ts.UTC().Format(time.RFC3339Nano)
}

func parseTimestamp(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse sqlite timestamp %q: %w", raw, err)
	}
	return parsed, nil
}
