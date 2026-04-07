package domain

import "time"

type SourceType string

const (
	SourceTypeGitHub SourceType = "github"
	SourceTypeGitLab SourceType = "gitlab"
)

type ResponseMode string

const (
	ResponseModeSnippet ResponseMode = "snippet"
	ResponseModeSummary ResponseMode = "summary"
)

func (r ResponseMode) Valid() bool {
	switch r {
	case ResponseModeSnippet, ResponseModeSummary:
		return true
	default:
		return false
	}
}

type SearchFilters struct {
	Repositories  []string `json:"repositories,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	Extensions    []string `json:"extensions,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	Page          int      `json:"page,omitempty"`
	PerPage       int      `json:"per_page,omitempty"`
}

type SearchRequest struct {
	RequestID       string        `json:"request_id"`
	CallerPrincipal string        `json:"caller_principal"`
	CallerRoles     []string      `json:"-"`
	SourceType      SourceType    `json:"source_type"`
	SourceHost      string        `json:"source_host"`
	QueryText       string        `json:"query_text"`
	Filters         SearchFilters `json:"filters"`
	MaxResults      int           `json:"max_results"`
	PolicyProfile   string        `json:"policy_profile"`
	ResponseMode    ResponseMode  `json:"response_mode"`
}

type FileReadRequest struct {
	RequestID       string     `json:"request_id"`
	CallerPrincipal string     `json:"caller_principal"`
	CallerRoles     []string   `json:"-"`
	SourceType      SourceType `json:"source_type"`
	SourceHost      string     `json:"source_host"`
	Repository      string     `json:"repository"`
	FilePath        string     `json:"file_path"`
	Ref             string     `json:"ref"`
	StartLine       int        `json:"start_line"`
	LineCount       int        `json:"line_count"`
	PolicyProfile   string     `json:"policy_profile"`
}

type MatchRange struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

type SearchResult struct {
	SourceType        SourceType        `json:"source_type"`
	SourceHost        string            `json:"source_host"`
	Repository        string            `json:"repository"`
	FilePath          string            `json:"file_path"`
	Ref               string            `json:"ref"`
	Language          string            `json:"language"`
	SnippetTextRaw    string            `json:"-"`
	MatchRanges       []MatchRange      `json:"match_ranges,omitempty"`
	SourceURL         string            `json:"source_url"`
	ConnectorMetadata map[string]string `json:"connector_metadata,omitempty"`
}

type FileContentResult struct {
	SourceType        SourceType        `json:"source_type"`
	SourceHost        string            `json:"source_host"`
	Repository        string            `json:"repository"`
	FilePath          string            `json:"file_path"`
	Ref               string            `json:"ref"`
	Language          string            `json:"language"`
	FullTextRaw       string            `json:"-"`
	SourceURL         string            `json:"source_url"`
	ConnectorMetadata map[string]string `json:"connector_metadata,omitempty"`
}

type DecisionAction string

const (
	DecisionAllow           DecisionAction = "allow"
	DecisionMask            DecisionAction = "mask"
	DecisionRewriteRequired DecisionAction = "rewrite_required"
	DecisionSuppress        DecisionAction = "suppress"
)

type PolicyDecision struct {
	Decision       DecisionAction    `json:"decision"`
	MatchedRules   []string          `json:"matched_rules,omitempty"`
	Transforms     []string          `json:"transforms,omitempty"`
	Replacements   []ReplacementRule `json:"-"`
	ExportAllowed  bool              `json:"export_allowed"`
	ModelAllowed   bool              `json:"model_allowed"`
	SummaryAllowed bool              `json:"summary_allowed"`
	Reason         string            `json:"reason,omitempty"`
}

type ReplacementRule struct {
	Literal     string
	Pattern     string
	Replacement string
}

type EvidenceItem struct {
	EvidenceID        string            `json:"evidence_id"`
	Repository        string            `json:"repository"`
	FilePath          string            `json:"file_path"`
	Ref               string            `json:"ref"`
	Language          string            `json:"language"`
	LineStart         int               `json:"line_start"`
	LineEnd           int               `json:"line_end"`
	SourceURL         string            `json:"source_url"`
	SnippetText       string            `json:"snippet_text,omitempty"`
	ReleaseMode       string            `json:"release_mode"`
	RedactionActions  []string          `json:"redaction_actions,omitempty"`
	SuppressionReason string            `json:"suppression_reason,omitempty"`
	AuditID           string            `json:"audit_id"`
	SummaryAllowed    bool              `json:"summary_allowed"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

type SanitizedResult = EvidenceItem

type DigestCitation struct {
	CitationID string `json:"citation_id"`
	EvidenceID string `json:"evidence_id"`
	Repository string `json:"repository"`
	FilePath   string `json:"file_path"`
	Ref        string `json:"ref"`
	LineStart  int    `json:"line_start"`
	LineEnd    int    `json:"line_end"`
}

type SearchDigest struct {
	SummaryText         string           `json:"summary_text,omitempty"`
	EvidenceCount       int              `json:"evidence_count"`
	SuppressedCount     int              `json:"suppressed_count"`
	TopRepositories     []string         `json:"top_repositories,omitempty"`
	FollowUpSuggestions []string         `json:"follow_up_suggestions,omitempty"`
	Citations           []DigestCitation `json:"citations,omitempty"`
}

type TruncationInfo struct {
	ResultsTruncated      bool `json:"results_truncated"`
	SuppressedDueToBudget int  `json:"suppressed_due_to_budget"`
	RemainingHitsEstimate int  `json:"remaining_hits_estimate"`
}

type SearchResponse struct {
	RequestID  string          `json:"request_id"`
	AuditID    string          `json:"audit_id"`
	Results    []EvidenceItem  `json:"results"`
	Digest     *SearchDigest   `json:"digest,omitempty"`
	Truncation *TruncationInfo `json:"truncation,omitempty"`
}

type FileReadResponse struct {
	RequestID  string          `json:"request_id"`
	AuditID    string          `json:"audit_id"`
	Result     EvidenceItem    `json:"result"`
	Truncation *TruncationInfo `json:"truncation,omitempty"`
}

type AuditRequestRecord struct {
	RequestID       string        `json:"request_id"`
	CallerPrincipal string        `json:"caller_principal"`
	CallerRoles     []string      `json:"caller_roles,omitempty"`
	SourceType      SourceType    `json:"source_type"`
	SourceHost      string        `json:"source_host"`
	QueryText       string        `json:"query_text"`
	Filters         SearchFilters `json:"filters"`
	PolicyProfile   string        `json:"policy_profile"`
	CreatedAt       time.Time     `json:"created_at"`
}

type AuditDecisionRecord struct {
	RequestID         string         `json:"request_id"`
	AuditID           string         `json:"audit_id"`
	EvidenceID        string         `json:"evidence_id,omitempty"`
	Repository        string         `json:"repository"`
	FilePath          string         `json:"file_path"`
	LineStart         int            `json:"line_start"`
	LineEnd           int            `json:"line_end"`
	Decision          DecisionAction `json:"decision"`
	MatchedRules      []string       `json:"matched_rules,omitempty"`
	ModelInvoked      bool           `json:"model_invoked"`
	ReleaseMode       string         `json:"release_mode"`
	SuppressionReason string         `json:"suppression_reason,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
}

type AuditDeliveryRecord struct {
	RequestID             string         `json:"request_id"`
	AuditID               string         `json:"audit_id"`
	SnippetCount          int            `json:"snippet_count"`
	RawHitCount           int            `json:"raw_hit_count"`
	EvidenceCount         int            `json:"evidence_count"`
	SuppressedCount       int            `json:"suppressed_count"`
	ResponseBytes         int            `json:"response_bytes"`
	ConnectorStats        map[string]int `json:"connector_stats,omitempty"`
	LatencyMillis         int64          `json:"latency_millis"`
	ResultsTruncated      bool           `json:"results_truncated"`
	SuppressedDueToBudget int            `json:"suppressed_due_to_budget"`
	RemainingHitsEstimate int            `json:"remaining_hits_estimate"`
	SummaryGenerated      bool           `json:"summary_generated"`
	SummaryCitationIDs    []string       `json:"summary_citation_ids,omitempty"`
	CreatedAt             time.Time      `json:"created_at"`
}

type AuditBundle struct {
	Request   AuditRequestRecord    `json:"request"`
	Decisions []AuditDecisionRecord `json:"decisions"`
	Delivery  AuditDeliveryRecord   `json:"delivery"`
}
