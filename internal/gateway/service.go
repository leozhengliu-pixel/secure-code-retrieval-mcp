package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
)

type Connector interface {
	Search(ctx context.Context, req domain.SearchRequest) ([]domain.SearchResult, error)
}

type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req domain.SearchRequest, result domain.SearchResult) (domain.PolicyDecision, error)
}

type Sanitizer interface {
	Sanitize(ctx context.Context, req domain.SearchRequest, result domain.SearchResult, decision domain.PolicyDecision) (domain.SanitizedResult, bool, error)
}

type Auditor interface {
	RecordRequest(ctx context.Context, record domain.AuditRequestRecord) (string, error)
	RecordDecision(ctx context.Context, record domain.AuditDecisionRecord) error
	RecordDelivery(ctx context.Context, record domain.AuditDeliveryRecord) error
	GetBundle(ctx context.Context, requestID string) (domain.AuditBundle, error)
}

type Dependencies struct {
	Logger    *slog.Logger
	Timeout   time.Duration
	GitHub    Connector
	GitLab    Connector
	Policy    PolicyEvaluator
	Sanitizer Sanitizer
	Auditor   Auditor
}

type Service struct {
	logger    *slog.Logger
	timeout   time.Duration
	github    Connector
	gitlab    Connector
	policy    PolicyEvaluator
	sanitizer Sanitizer
	auditor   Auditor
}

type SearchInput = domain.SearchRequest

func NewService(deps Dependencies) *Service {
	return &Service{
		logger:    deps.Logger,
		timeout:   deps.Timeout,
		github:    deps.GitHub,
		gitlab:    deps.GitLab,
		policy:    deps.Policy,
		sanitizer: deps.Sanitizer,
		auditor:   deps.Auditor,
	}
}

func (s *Service) Search(ctx context.Context, req SearchInput) (domain.SearchResponse, error) {
	if req.TenantID == "" {
		return domain.SearchResponse{}, domain.ErrMissingTenant
	}
	if req.CallerPrincipal == "" {
		return domain.SearchResponse{}, domain.ErrMissingPrincipal
	}
	if req.QueryText == "" || req.SourceHost == "" || req.SourceType == "" || !req.ResponseMode.Valid() {
		return domain.SearchResponse{}, domain.ErrInvalidRequest
	}
	if req.MaxResults <= 0 {
		req.MaxResults = 10
	}
	if req.RequestID == "" {
		req.RequestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
	}

	ctx = domain.WithRequestMetadata(ctx, req.RequestID, req.TenantID, req.CallerPrincipal)
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	auditID, err := s.auditor.RecordRequest(ctx, domain.AuditRequestRecord{
		RequestID:       req.RequestID,
		TenantID:        req.TenantID,
		CallerPrincipal: req.CallerPrincipal,
		SourceType:      req.SourceType,
		SourceHost:      req.SourceHost,
		QueryText:       req.QueryText,
		Filters:         req.Filters,
		PolicyProfile:   req.PolicyProfile,
		CreatedAt:       time.Now().UTC(),
	})
	if err != nil {
		return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrAuditPersistence, err)
	}

	results, err := s.connectorFor(req.SourceType).Search(ctx, req)
	if err != nil {
		return domain.SearchResponse{}, err
	}

	sanitized := make([]domain.SanitizedResult, 0, len(results))
	modelCalls := 0
	for _, result := range results {
		decision, err := s.policy.Evaluate(ctx, req, result)
		if err != nil {
			return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrPolicyEvaluation, err)
		}
		item, modelInvoked, err := s.sanitizer.Sanitize(ctx, req, result, decision)
		if err != nil {
			return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrSanitization, err)
		}
		item.AuditID = auditID
		sanitized = append(sanitized, item)
		if modelInvoked {
			modelCalls++
		}
		if err := s.auditor.RecordDecision(ctx, domain.AuditDecisionRecord{
			RequestID:         req.RequestID,
			AuditID:           auditID,
			Repository:        result.Repository,
			FilePath:          result.FilePath,
			Decision:          decision.Decision,
			MatchedRules:      decision.MatchedRules,
			ModelInvoked:      modelInvoked,
			ReleaseMode:       item.ReleaseMode,
			SuppressionReason: item.SuppressionReason,
			CreatedAt:         time.Now().UTC(),
		}); err != nil {
			return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrAuditPersistence, err)
		}
	}

	response := domain.SearchResponse{RequestID: req.RequestID, AuditID: auditID, Results: sanitized}
	payload, _ := json.Marshal(response)
	if err := s.auditor.RecordDelivery(ctx, domain.AuditDeliveryRecord{
		RequestID:      req.RequestID,
		AuditID:        auditID,
		SnippetCount:   len(sanitized),
		ResponseBytes:  len(payload),
		ConnectorStats: map[string]int{"results": len(results), "model_invocations": modelCalls},
		LatencyMillis:  time.Since(start).Milliseconds(),
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrAuditPersistence, err)
	}

	s.logger.Info("search completed", "request_id", req.RequestID, "audit_id", auditID, "results", len(sanitized))
	return response, nil
}

func (s *Service) GetAudit(ctx context.Context, requestID string) (domain.AuditBundle, error) {
	return s.auditor.GetBundle(ctx, requestID)
}

func (s *Service) connectorFor(sourceType domain.SourceType) Connector {
	switch sourceType {
	case domain.SourceTypeGitHub:
		return s.github
	case domain.SourceTypeGitLab:
		return s.gitlab
	default:
		return unsupportedConnector{}
	}
}

type unsupportedConnector struct{}

func (unsupportedConnector) Search(context.Context, domain.SearchRequest) ([]domain.SearchResult, error) {
	return nil, errors.New("unsupported source type")
}
