package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/metrics"
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
	Logger               *slog.Logger
	Timeout              time.Duration
	DefaultPolicyProfile string
	AdminRole            string
	Metrics              *metrics.Metrics
	GitHub               Connector
	GitLab               Connector
	Policy               PolicyEvaluator
	Sanitizer            Sanitizer
	Auditor              Auditor
}

type Service struct {
	logger               *slog.Logger
	timeout              time.Duration
	defaultPolicyProfile string
	adminRole            string
	metrics              *metrics.Metrics
	github               Connector
	gitlab               Connector
	policy               PolicyEvaluator
	sanitizer            Sanitizer
	auditor              Auditor
}

type SearchInput = domain.SearchRequest

func NewService(deps Dependencies) *Service {
	return &Service{
		logger:               deps.Logger,
		timeout:              deps.Timeout,
		defaultPolicyProfile: deps.DefaultPolicyProfile,
		adminRole:            deps.AdminRole,
		metrics:              deps.Metrics,
		github:               deps.GitHub,
		gitlab:               deps.GitLab,
		policy:               deps.Policy,
		sanitizer:            deps.Sanitizer,
		auditor:              deps.Auditor,
	}
}

func (s *Service) Search(ctx context.Context, req SearchInput) (domain.SearchResponse, error) {
	if req.CallerPrincipal == "" {
		return domain.SearchResponse{}, domain.ErrMissingPrincipal
	}
	if req.QueryText == "" || req.SourceHost == "" || req.SourceType == "" || !req.ResponseMode.Valid() {
		return domain.SearchResponse{}, domain.ErrInvalidRequest
	}
	if req.PolicyProfile == "" {
		req.PolicyProfile = s.defaultPolicyProfile
	}
	if req.PolicyProfile == "" {
		return domain.SearchResponse{}, domain.ErrInvalidRequest
	}
	if req.MaxResults <= 0 {
		req.MaxResults = 10
	}
	if req.RequestID == "" {
		req.RequestID = fmt.Sprintf("req_%d", time.Now().UnixNano())
	}

	ctx = domain.WithRequestMetadata(ctx, req.RequestID, req.CallerPrincipal, req.CallerRoles)
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	status := "ok"
	defer func() {
		if s.metrics != nil {
			s.metrics.RequestTotal.WithLabelValues("http_or_mcp", string(req.SourceType), status).Inc()
			s.metrics.RequestDuration.WithLabelValues("http_or_mcp", string(req.SourceType)).Observe(time.Since(start).Seconds())
		}
	}()
	auditID, err := s.auditor.RecordRequest(ctx, domain.AuditRequestRecord{
		RequestID:       req.RequestID,
		CallerPrincipal: req.CallerPrincipal,
		CallerRoles:     req.CallerRoles,
		SourceType:      req.SourceType,
		SourceHost:      req.SourceHost,
		QueryText:       req.QueryText,
		Filters:         req.Filters,
		PolicyProfile:   req.PolicyProfile,
		CreatedAt:       time.Now().UTC(),
	})
	if err != nil {
		status = "audit_error"
		return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrAuditPersistence, err)
	}

	results, err := s.connectorFor(req.SourceType).Search(ctx, req)
	if err != nil {
		status = "connector_error"
		s.observeConnectorError(req.SourceType, err)
		return domain.SearchResponse{}, err
	}

	sanitized := make([]domain.SanitizedResult, 0, len(results))
	modelCalls := 0
	for _, result := range results {
		decision, err := s.policy.Evaluate(ctx, req, result)
		if err != nil {
			status = "policy_error"
			return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrPolicyEvaluation, err)
		}
		if s.metrics != nil {
			s.metrics.PolicyHits.WithLabelValues(req.PolicyProfile, string(decision.Decision)).Inc()
		}
		item, modelInvoked, err := s.sanitizer.Sanitize(ctx, req, result, decision)
		if err != nil {
			status = "sanitize_error"
			return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrSanitization, err)
		}
		item.AuditID = auditID
		sanitized = append(sanitized, item)
		if modelInvoked {
			modelCalls++
			if s.metrics != nil {
				s.metrics.ModelInvocations.WithLabelValues(req.PolicyProfile, "configured").Inc()
			}
		}
		if item.ReleaseMode == "suppressed" && s.metrics != nil {
			s.metrics.SanitizeSuppress.WithLabelValues(req.PolicyProfile).Inc()
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
			status = "audit_error"
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
		status = "audit_error"
		return domain.SearchResponse{}, fmt.Errorf("%w: %v", domain.ErrAuditPersistence, err)
	}

	s.logger.Info("search completed", "request_id", req.RequestID, "audit_id", auditID, "results", len(sanitized))
	return response, nil
}

func (s *Service) GetAudit(ctx context.Context, requestID string) (domain.AuditBundle, error) {
	bundle, err := s.auditor.GetBundle(ctx, requestID)
	if err != nil {
		return domain.AuditBundle{}, fmt.Errorf("%w: %v", domain.ErrNotFound, err)
	}
	principal := domain.PrincipalFromContext(ctx)
	roles := domain.RolesFromContext(ctx)
	if principal == "" {
		return domain.AuditBundle{}, domain.ErrUnauthorized
	}
	if principal != bundle.Request.CallerPrincipal && !containsRole(roles, s.adminRole) {
		return domain.AuditBundle{}, domain.ErrForbidden
	}
	return bundle, nil
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

func (s *Service) observeConnectorError(sourceType domain.SourceType, err error) {
	if s.metrics == nil {
		return
	}
	errorClass := "upstream"
	switch {
	case errors.Is(err, domain.ErrUnauthorized):
		errorClass = "auth"
	case errors.Is(err, domain.ErrProxyAuth):
		errorClass = "proxy_auth"
	case errors.Is(err, domain.ErrProxyTimeout):
		errorClass = "proxy_timeout"
	case errors.Is(err, domain.ErrProxyConnect):
		errorClass = "proxy_connect"
	case strings.Contains(strings.ToLower(err.Error()), "rate"):
		errorClass = "rate_limit"
	}
	s.metrics.ConnectorErrors.WithLabelValues(string(sourceType), errorClass).Inc()
}

func containsRole(roles []string, role string) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}
