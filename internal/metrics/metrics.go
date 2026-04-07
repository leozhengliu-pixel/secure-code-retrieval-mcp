package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	RequestTotal     *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	ConnectorErrors  *prometheus.CounterVec
	PolicyHits       *prometheus.CounterVec
	SanitizeSuppress *prometheus.CounterVec
	ModelInvocations *prometheus.CounterVec
	RawHits          *prometheus.CounterVec
	EvidenceItems    *prometheus.CounterVec
	SummaryGenerated *prometheus.CounterVec
	BudgetTruncated  *prometheus.CounterVec
	ProxyUsage       *prometheus.CounterVec
	ReadyState       *prometheus.GaugeVec
	registry         *prometheus.Registry
}

func New() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		RequestTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_requests_total",
			Help: "Total requests processed.",
		}, []string{"transport", "source_type", "status"}),
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "scrm_request_duration_seconds",
			Help:    "Request latency.",
			Buckets: prometheus.DefBuckets,
		}, []string{"transport", "source_type"}),
		ConnectorErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_connector_errors_total",
			Help: "Connector errors by class.",
		}, []string{"source_type", "error_class"}),
		PolicyHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_policy_hits_total",
			Help: "Policy rule hits by decision.",
		}, []string{"policy_profile", "decision"}),
		SanitizeSuppress: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_sanitize_suppressed_total",
			Help: "Suppressed result count.",
		}, []string{"policy_profile"}),
		ModelInvocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_model_invocations_total",
			Help: "Model rewrite invocations.",
		}, []string{"policy_profile", "provider"}),
		RawHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_raw_hits_total",
			Help: "Raw connector hits returned.",
		}, []string{"source_type"}),
		EvidenceItems: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_evidence_items_total",
			Help: "Evidence items emitted after sanitization and budget shaping.",
		}, []string{"policy_profile"}),
		SummaryGenerated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_summary_generated_total",
			Help: "Summary responses generated.",
		}, []string{"policy_profile"}),
		BudgetTruncated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_budget_truncated_total",
			Help: "Responses truncated due to digest budgets.",
		}, []string{"policy_profile"}),
		ProxyUsage: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scrm_proxy_usage_total",
			Help: "Outbound requests that used a proxy.",
		}, []string{"target", "via_proxy"}),
		ReadyState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "scrm_ready_state",
			Help: "Readiness state by dependency.",
		}, []string{"dependency"}),
		registry: registry,
	}
	registry.MustRegister(
		m.RequestTotal,
		m.RequestDuration,
		m.ConnectorErrors,
		m.PolicyHits,
		m.SanitizeSuppress,
		m.ModelInvocations,
		m.RawHits,
		m.EvidenceItems,
		m.SummaryGenerated,
		m.BudgetTruncated,
		m.ProxyUsage,
		m.ReadyState,
	)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
