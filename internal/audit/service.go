package audit

import (
	"context"
	"fmt"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
)

type Repository interface {
	EnsureSchema(ctx context.Context) error
	CreateRequest(ctx context.Context, auditID string, record domain.AuditRequestRecord) error
	CreateDecision(ctx context.Context, record domain.AuditDecisionRecord) error
	CreateDelivery(ctx context.Context, record domain.AuditDeliveryRecord) error
	GetBundle(ctx context.Context, requestID string) (domain.AuditBundle, error)
}

type Service struct{ repository Repository }

func NewService(repository Repository) *Service { return &Service{repository: repository} }

func (s *Service) RecordRequest(ctx context.Context, record domain.AuditRequestRecord) (string, error) {
	if err := s.repository.EnsureSchema(ctx); err != nil {
		return "", err
	}
	auditID := fmt.Sprintf("audit_%d", time.Now().UnixNano())
	if err := s.repository.CreateRequest(ctx, auditID, record); err != nil {
		return "", err
	}
	return auditID, nil
}

func (s *Service) RecordDecision(ctx context.Context, record domain.AuditDecisionRecord) error {
	return s.repository.CreateDecision(ctx, record)
}
func (s *Service) RecordDelivery(ctx context.Context, record domain.AuditDeliveryRecord) error {
	return s.repository.CreateDelivery(ctx, record)
}
func (s *Service) GetBundle(ctx context.Context, requestID string) (domain.AuditBundle, error) {
	return s.repository.GetBundle(ctx, requestID)
}
