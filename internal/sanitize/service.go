package sanitize

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type Rewriter interface {
	Rewrite(ctx context.Context, snippet string) (string, error)
}

type ProviderFactory struct {
	providers []Rewriter
	logger    *slog.Logger
}

func NewProviderFactory(cfgs []config.ModelEndpoint, defaultProxy *config.ProxyConfig, logger *slog.Logger) *ProviderFactory {
	factory := &ProviderFactory{logger: logger}
	for _, cfg := range cfgs {
		if provider := newProvider(cfg, defaultProxy, logger); provider != nil {
			factory.providers = append(factory.providers, provider)
		}
	}
	return factory
}

func (f *ProviderFactory) First() Rewriter {
	if len(f.providers) == 0 {
		return nil
	}
	return f.providers[0]
}

type Service struct {
	factory *ProviderFactory
	logger  *slog.Logger
}

func NewService(factory *ProviderFactory, logger *slog.Logger) *Service {
	return &Service{factory: factory, logger: logger}
}

func (s *Service) Sanitize(ctx context.Context, req domain.SearchRequest, result domain.SearchResult, decision domain.PolicyDecision) (domain.SanitizedResult, bool, error) {
	sanitized := domain.SanitizedResult{
		Repository: result.Repository,
		FilePath:   result.FilePath,
		Ref:        result.Ref,
		Language:   result.Language,
		SourceURL:  result.SourceURL,
		Metadata:   result.ConnectorMetadata,
	}

	switch decision.Decision {
	case domain.DecisionSuppress:
		sanitized.ReleaseMode = "suppressed"
		sanitized.RedactionActions = []string{string(domain.DecisionSuppress)}
		sanitized.SuppressionReason = decision.Reason
		return sanitized, false, nil
	case domain.DecisionAllow:
		sanitized.ReleaseMode = string(req.ResponseMode)
		sanitized.SnippetText = stripComments(result.SnippetTextRaw)
		return sanitized, false, nil
	}

	bounded := applyDeterministicMask(result.SnippetTextRaw)
	actions := []string{"deterministic_mask"}
	modelInvoked := false

	if decision.Decision == domain.DecisionRewriteRequired {
		if !decision.ExportAllowed {
			sanitized.ReleaseMode = "suppressed"
			sanitized.RedactionActions = []string{string(domain.DecisionSuppress)}
			sanitized.SuppressionReason = "policy marked content non-exportable"
			return sanitized, false, nil
		}
		provider := s.factory.First()
		if provider != nil && decision.ModelAllowed {
			rewritten, err := provider.Rewrite(ctx, bounded)
			if err == nil {
				bounded = rewritten
				modelInvoked = true
				actions = append(actions, "model_rewrite")
			} else {
				s.logger.Warn("model rewrite failed", "err", err)
				sanitized.ReleaseMode = "suppressed"
				sanitized.RedactionActions = []string{string(domain.DecisionSuppress)}
				sanitized.SuppressionReason = "model rewrite failed and policy requires rewrite"
				return sanitized, false, nil
			}
		} else {
			sanitized.ReleaseMode = "suppressed"
			sanitized.RedactionActions = []string{string(domain.DecisionSuppress)}
			sanitized.SuppressionReason = "rewrite required but model unavailable"
			return sanitized, false, nil
		}
	}

	if !validateOutput(bounded) {
		return domain.SanitizedResult{}, false, fmt.Errorf("post-sanitization validation failed")
	}
	sanitized.SnippetText = stripComments(bounded)
	sanitized.ReleaseMode = string(req.ResponseMode)
	sanitized.RedactionActions = actions
	return sanitized, modelInvoked, nil
}

func applyDeterministicMask(snippet string) string {
	maskers := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|token|secret)\s*[:=]\s*["'][^"']+["']`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	}
	out := snippet
	for _, re := range maskers {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

func validateOutput(snippet string) bool {
	for _, forbidden := range []string{"AKIA", "BEGIN PRIVATE KEY"} {
		if strings.Contains(snippet, forbidden) {
			return false
		}
	}
	return true
}

func stripComments(snippet string) string {
	lines := strings.Split(snippet, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}
