package sqlite

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

func TestAuditRepositoryRoundTripsBundle(t *testing.T) {
	repository, err := NewAuditRepository(config.DatabaseConfig{
		SQLitePath: filepath.Join(t.TempDir(), "audit.db"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewMigrator(repository.DB()).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Round(0)
	if err := repository.CreateRequest(context.Background(), "audit_1", domain.AuditRequestRecord{
		RequestID:       "req_1",
		CallerPrincipal: "alice",
		CallerRoles:     []string{"scrm_admin"},
		SourceType:      domain.SourceTypeGitHub,
		SourceHost:      "github.example.com",
		QueryText:       "token",
		PolicyProfile:   "default",
		CreatedAt:       now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateDecision(context.Background(), domain.AuditDecisionRecord{
		RequestID:    "req_1",
		AuditID:      "audit_1",
		EvidenceID:   "e1",
		Repository:   "acme/repo",
		FilePath:     "main.go",
		LineStart:    1,
		LineEnd:      2,
		Decision:     domain.DecisionAllow,
		MatchedRules: []string{"allow-basic"},
		ReleaseMode:  "snippet",
		CreatedAt:    now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateDelivery(context.Background(), domain.AuditDeliveryRecord{
		RequestID:          "req_1",
		AuditID:            "audit_1",
		SnippetCount:       1,
		RawHitCount:        1,
		EvidenceCount:      1,
		SuppressedCount:    0,
		ResponseBytes:      42,
		ConnectorStats:     map[string]int{"results": 1},
		LatencyMillis:      7,
		SummaryGenerated:   false,
		SummaryCitationIDs: []string{"c1"},
		CreatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}

	bundle, err := repository.GetBundle(context.Background(), "req_1")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Request.CallerPrincipal != "alice" {
		t.Fatalf("unexpected caller principal: %q", bundle.Request.CallerPrincipal)
	}
	if len(bundle.Request.CallerRoles) != 1 || bundle.Request.CallerRoles[0] != "scrm_admin" {
		t.Fatalf("unexpected caller roles: %#v", bundle.Request.CallerRoles)
	}
	if !bundle.Request.CreatedAt.Equal(now) {
		t.Fatalf("unexpected request created_at: got %s want %s", bundle.Request.CreatedAt, now)
	}
	if len(bundle.Decisions) != 1 || !bundle.Decisions[0].CreatedAt.Equal(now) {
		t.Fatalf("unexpected decisions: %#v", bundle.Decisions)
	}
	if bundle.Delivery.AuditID != "audit_1" || !bundle.Delivery.CreatedAt.Equal(now) {
		t.Fatalf("unexpected delivery: %#v", bundle.Delivery)
	}
	if len(bundle.Delivery.SummaryCitationIDs) != 1 || bundle.Delivery.SummaryCitationIDs[0] != "c1" {
		t.Fatalf("unexpected citations: %#v", bundle.Delivery.SummaryCitationIDs)
	}
}
