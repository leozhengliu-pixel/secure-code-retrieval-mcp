package gateway

import (
	"fmt"
	"sort"
	"strings"

	"secure-code-retrieval-mcp/internal/domain"
)

const (
	defaultContextBeforeLines    = 2
	defaultContextAfterLines     = 2
	defaultMaxWindowLines        = 8
	defaultMaxEvidenceItems      = 8
	defaultMaxTotalEvidenceChars = 2400
	defaultMaxSummaryInputItems  = 5
	defaultMaxSummaryOutputChars = 1200
)

type DigestBuilder interface {
	Build(req domain.SearchRequest, rawHits []domain.SearchResult, items []domain.EvidenceItem) ([]domain.EvidenceItem, *domain.SearchDigest, *domain.TruncationInfo)
}

type deterministicDigestBuilder struct{}

func NewDigestBuilder() DigestBuilder {
	return deterministicDigestBuilder{}
}

func (deterministicDigestBuilder) Build(req domain.SearchRequest, rawHits []domain.SearchResult, items []domain.EvidenceItem) ([]domain.EvidenceItem, *domain.SearchDigest, *domain.TruncationInfo) {
	deduped := dedupeEvidence(items)
	sortEvidence(deduped)

	totalChars := 0
	kept := make([]domain.EvidenceItem, 0, min(len(deduped), defaultMaxEvidenceItems))
	suppressedDueToBudget := 0
	for _, item := range deduped {
		nextChars := len(item.SnippetText)
		if len(kept) >= defaultMaxEvidenceItems || totalChars+nextChars > defaultMaxTotalEvidenceChars {
			suppressedDueToBudget++
			continue
		}
		kept = append(kept, item)
		totalChars += nextChars
	}

	truncation := &domain.TruncationInfo{
		ResultsTruncated:      suppressedDueToBudget > 0 || len(rawHits) > len(kept),
		SuppressedDueToBudget: suppressedDueToBudget,
		RemainingHitsEstimate: max(0, len(rawHits)-len(kept)),
	}
	if !truncation.ResultsTruncated && req.ResponseMode == domain.ResponseModeSnippet {
		truncation = nil
	}

	if req.ResponseMode != domain.ResponseModeSummary {
		return kept, nil, truncation
	}

	digest := buildDeterministicDigest(kept)
	return kept, digest, truncation
}

func BoundSearchResult(result domain.SearchResult) domain.SearchResult {
	lines := strings.Split(result.SnippetTextRaw, "\n")
	if len(lines) == 0 {
		return result
	}
	bounded := result
	startIdx := 0
	endIdx := len(lines)
	if endIdx-startIdx > defaultMaxWindowLines {
		endIdx = defaultMaxWindowLines
	}
	bounded.SnippetTextRaw = strings.Join(lines[startIdx:endIdx], "\n")
	if len(result.MatchRanges) > 0 {
		base := result.MatchRanges[0].StartLine
		if base <= 0 {
			base = 1
		}
		bounded.MatchRanges = []domain.MatchRange{{
			StartLine: max(1, base-defaultContextBeforeLines),
			EndLine:   max(1, base-defaultContextBeforeLines) + (endIdx - startIdx) - 1,
		}}
	} else {
		bounded.MatchRanges = []domain.MatchRange{{StartLine: 1, EndLine: endIdx - startIdx}}
	}
	return bounded
}

func buildDeterministicDigest(items []domain.EvidenceItem) *domain.SearchDigest {
	evidence := make([]domain.EvidenceItem, 0, len(items))
	suppressedCount := 0
	repoCounts := make(map[string]int)
	for _, item := range items {
		if item.ReleaseMode == "suppressed" {
			suppressedCount++
			continue
		}
		if !item.SummaryAllowed {
			continue
		}
		evidence = append(evidence, item)
		repoCounts[item.Repository]++
	}
	if len(evidence) == 0 {
		if suppressedCount == 0 {
			return nil
		}
		return &domain.SearchDigest{
			SummaryText:     "Insufficient safe evidence available to generate a summary.",
			EvidenceCount:   0,
			SuppressedCount: suppressedCount,
		}
	}

	topRepos := topRepositories(repoCounts)
	inputItems := evidence
	if len(inputItems) > defaultMaxSummaryInputItems {
		inputItems = inputItems[:defaultMaxSummaryInputItems]
	}
	citations := make([]domain.DigestCitation, 0, len(inputItems))
	lines := []string{
		fmt.Sprintf("Found %d safe evidence items across %d repositories.", len(evidence), len(repoCounts)),
	}
	for i, item := range inputItems {
		citationID := fmt.Sprintf("c%d", i+1)
		citations = append(citations, domain.DigestCitation{
			CitationID: citationID,
			EvidenceID: item.EvidenceID,
			Repository: item.Repository,
			FilePath:   item.FilePath,
			Ref:        item.Ref,
			LineStart:  item.LineStart,
			LineEnd:    item.LineEnd,
		})
		lines = append(lines, fmt.Sprintf("[%s] %s %s lines %d-%d", citationID, item.Repository, item.FilePath, item.LineStart, item.LineEnd))
	}
	summary := strings.Join(lines, "\n")
	if len(summary) > defaultMaxSummaryOutputChars {
		summary = summary[:defaultMaxSummaryOutputChars]
	}
	return &domain.SearchDigest{
		SummaryText:         summary,
		EvidenceCount:       len(evidence),
		SuppressedCount:     suppressedCount,
		TopRepositories:     topRepos,
		FollowUpSuggestions: buildFollowUpSuggestions(evidence),
		Citations:           citations,
	}
}

func dedupeEvidence(items []domain.EvidenceItem) []domain.EvidenceItem {
	seen := make(map[string]struct{}, len(items))
	out := make([]domain.EvidenceItem, 0, len(items))
	for _, item := range items {
		key := strings.Join([]string{item.Repository, item.FilePath, item.Ref, item.SnippetText, item.ReleaseMode}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func sortEvidence(items []domain.EvidenceItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].ReleaseMode == "suppressed" && items[j].ReleaseMode != "suppressed" {
			return false
		}
		if items[i].ReleaseMode != "suppressed" && items[j].ReleaseMode == "suppressed" {
			return true
		}
		iRange := items[i].LineEnd - items[i].LineStart
		jRange := items[j].LineEnd - items[j].LineStart
		if iRange != jRange {
			return iRange < jRange
		}
		if len(items[i].SnippetText) != len(items[j].SnippetText) {
			return len(items[i].SnippetText) < len(items[j].SnippetText)
		}
		if items[i].Repository != items[j].Repository {
			return items[i].Repository < items[j].Repository
		}
		return items[i].FilePath < items[j].FilePath
	})
}

func topRepositories(repoCounts map[string]int) []string {
	type repoCount struct {
		name  string
		count int
	}
	repos := make([]repoCount, 0, len(repoCounts))
	for name, count := range repoCounts {
		repos = append(repos, repoCount{name: name, count: count})
	}
	sort.Slice(repos, func(i, j int) bool {
		if repos[i].count != repos[j].count {
			return repos[i].count > repos[j].count
		}
		return repos[i].name < repos[j].name
	})
	out := make([]string, 0, len(repos))
	for _, repo := range repos {
		out = append(out, repo.name)
	}
	return out
}

func buildFollowUpSuggestions(items []domain.EvidenceItem) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 3)
	for _, item := range items {
		suggestion := fmt.Sprintf("Inspect %s at %s around lines %d-%d", item.Repository, item.FilePath, item.LineStart, item.LineEnd)
		if _, ok := seen[suggestion]; ok {
			continue
		}
		seen[suggestion] = struct{}{}
		out = append(out, suggestion)
		if len(out) == 3 {
			break
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
