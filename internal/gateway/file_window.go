package gateway

import (
	"fmt"
	"strings"

	"secure-code-retrieval-mcp/internal/domain"
)

func buildFileWindow(content domain.FileContentResult, startLine, lineCount int) (domain.SearchResult, *domain.TruncationInfo, error) {
	lines := strings.Split(content.FullTextRaw, "\n")
	startIdx := startLine - 1
	if startIdx < 0 {
		startIdx = 0
	}
	if startIdx >= len(lines) {
		return domain.SearchResult{}, nil, fmt.Errorf("%w: start_line beyond file length", domain.ErrInvalidRequest)
	}
	endIdx := startIdx + lineCount
	if endIdx > len(lines) {
		endIdx = len(lines)
	}
	windowLines := lines[startIdx:endIdx]
	truncation := &domain.TruncationInfo{
		ResultsTruncated:      startIdx > 0 || endIdx < len(lines),
		SuppressedDueToBudget: 0,
		RemainingHitsEstimate: max(0, len(lines)-endIdx),
	}
	if !truncation.ResultsTruncated {
		truncation = nil
	}
	return domain.SearchResult{
		SourceType:        content.SourceType,
		SourceHost:        content.SourceHost,
		Repository:        content.Repository,
		FilePath:          content.FilePath,
		Ref:               content.Ref,
		Language:          content.Language,
		SnippetTextRaw:    strings.Join(windowLines, "\n"),
		MatchRanges:       []domain.MatchRange{{StartLine: startLine, EndLine: startLine + len(windowLines) - 1}},
		SourceURL:         content.SourceURL,
		ConnectorMetadata: content.ConnectorMetadata,
	}, truncation, nil
}
