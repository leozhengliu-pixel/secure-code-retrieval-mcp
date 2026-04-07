package app

import (
	"context"
	"fmt"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/metrics"
)

type readinessCheck func(context.Context) error

type readinessProbe struct {
	metrics *metrics.Metrics
	checks  map[string]readinessCheck
}

func newReadinessProbe(metrics *metrics.Metrics, checks map[string]readinessCheck) *readinessProbe {
	return &readinessProbe{metrics: metrics, checks: checks}
}

func (p *readinessProbe) Check(ctx context.Context) map[string]string {
	results := make(map[string]string, len(p.checks))
	for name, check := range p.checks {
		if err := check(ctx); err != nil {
			results[name] = err.Error()
			if p.metrics != nil {
				p.metrics.ReadyState.WithLabelValues(name).Set(0)
			}
			continue
		}
		results[name] = "ok"
		if p.metrics != nil {
			p.metrics.ReadyState.WithLabelValues(name).Set(1)
		}
	}
	return results
}

func readinessError(results map[string]string) error {
	for name, result := range results {
		if result != "ok" {
			return fmt.Errorf("%w: %s=%s", domain.ErrNotReady, name, result)
		}
	}
	return nil
}
