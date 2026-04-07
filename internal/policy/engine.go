package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"secure-code-retrieval-mcp/internal/config"
	"secure-code-retrieval-mcp/internal/domain"
)

type compiledRule struct {
	name          string
	action        domain.DecisionAction
	literal       string
	pattern       *regexp.Regexp
	replacement   string
	modelAllowed  bool
	exportAllowed bool
}

type profile struct {
	name            string
	repositoryAllow []string
	repositoryDeny  []string
	pathAllow       []string
	pathDeny        []string
	rules           []compiledRule
}

type Engine struct {
	profiles map[string]profile
}

func NewEngine(policies []config.PolicyProfile) (*Engine, error) {
	engine := &Engine{profiles: make(map[string]profile)}
	for _, policy := range policies {
		cp := profile{
			name:            policy.Name,
			repositoryAllow: policy.RepositoryAllow,
			repositoryDeny:  policy.RepositoryDeny,
			pathAllow:       policy.PathAllow,
			pathDeny:        policy.PathDeny,
		}
		for _, rule := range policy.Rules {
			cr := compiledRule{
				name:          rule.Name,
				action:        domain.DecisionAction(rule.Action),
				literal:       rule.Literal,
				replacement:   chooseReplacement(rule.Replacement),
				modelAllowed:  rule.ModelAllowed,
				exportAllowed: rule.ExportAllowed,
			}
			if rule.Pattern != "" {
				compiled, err := regexp.Compile(rule.Pattern)
				if err != nil {
					return nil, fmt.Errorf("compile rule %s: %w", rule.Name, err)
				}
				cr.pattern = compiled
			}
			cp.rules = append(cp.rules, cr)
		}
		engine.profiles[policy.Name] = cp
	}
	return engine, nil
}

func (e *Engine) Evaluate(_ context.Context, req domain.SearchRequest, result domain.SearchResult) (domain.PolicyDecision, error) {
	profile, ok := e.profiles[req.PolicyProfile]
	if req.PolicyProfile == "" || !ok {
		return domain.PolicyDecision{}, fmt.Errorf("policy profile %q not found", req.PolicyProfile)
	}
	if !allowedByScope(profile.repositoryAllow, profile.repositoryDeny, result.Repository) {
		return suppressDecision("repository restricted", "repository_scope"), nil
	}
	if !allowedByScope(profile.pathAllow, profile.pathDeny, result.FilePath) {
		return suppressDecision("path restricted", "path_scope"), nil
	}

	decision := domain.PolicyDecision{Decision: domain.DecisionAllow, ExportAllowed: true, ModelAllowed: false, SummaryAllowed: true}
	for _, rule := range profile.rules {
		if !matches(rule, result.SnippetTextRaw) {
			continue
		}
		decision.MatchedRules = append(decision.MatchedRules, rule.name)
		decision.Transforms = append(decision.Transforms, string(rule.action))
		decision.ExportAllowed = rule.exportAllowed
		decision.SummaryAllowed = rule.exportAllowed
		decision.ModelAllowed = decision.ModelAllowed || rule.modelAllowed
		if rule.action == domain.DecisionMask || rule.action == domain.DecisionRewriteRequired {
			decision.Replacements = append(decision.Replacements, domain.ReplacementRule{
				Literal:     rule.literal,
				Pattern:     compiledPattern(rule.pattern),
				Replacement: rule.replacement,
			})
		}
		switch rule.action {
		case domain.DecisionSuppress:
			return suppressDecision("content suppressed", rule.name), nil
		case domain.DecisionRewriteRequired:
			decision.Decision = domain.DecisionRewriteRequired
			decision.Reason = "rewrite required by policy"
		case domain.DecisionMask:
			if decision.Decision != domain.DecisionRewriteRequired {
				decision.Decision = domain.DecisionMask
			}
			decision.Reason = "mask required by policy"
		}
	}
	return decision, nil
}

func compiledPattern(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

func matches(rule compiledRule, snippet string) bool {
	if rule.literal != "" && strings.Contains(snippet, rule.literal) {
		return true
	}
	if rule.pattern != nil && rule.pattern.MatchString(snippet) {
		return true
	}
	return false
}

func allowedByScope(allow, deny []string, candidate string) bool {
	for _, blocked := range deny {
		if strings.Contains(candidate, blocked) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, accepted := range allow {
		if strings.Contains(candidate, accepted) {
			return true
		}
	}
	return false
}

func chooseReplacement(v string) string {
	if v == "" {
		return "[REDACTED]"
	}
	return v
}

func suppressDecision(reason, rule string) domain.PolicyDecision {
	return domain.PolicyDecision{
		Decision:       domain.DecisionSuppress,
		MatchedRules:   []string{rule},
		Transforms:     []string{string(domain.DecisionSuppress)},
		ExportAllowed:  false,
		ModelAllowed:   false,
		SummaryAllowed: false,
		Reason:         reason,
	}
}
