package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"secure-code-retrieval-mcp/internal/domain"
	"secure-code-retrieval-mcp/internal/gateway"
)

type Server struct {
	service *gateway.Service
	logger  *slog.Logger
}

const maxFileViewLineCount = 80
const (
	defaultBrowseDepth      = 1
	maxBrowseDepth          = 3
	defaultBrowseMaxEntries = 100
	maxBrowseMaxEntries     = 200
)

func NewServer(service *gateway.Service, logger *slog.Logger) *Server {
	return &Server{service: service, logger: logger}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := domain.RequestIDFromContext(r.Context())
	principal := domain.PrincipalFromContext(r.Context())
	defer func() {
		if rec := recover(); rec != nil {
			s.logger.Error("mcp transport panic", "request_id", requestID, "caller_principal", principal, "panic", rec)
			panic(rec)
		}
	}()
	switch r.Method {
	case http.MethodGet:
		s.logTransport(r, requestID, principal, start, http.StatusMethodNotAllowed, "method_not_allowed", nil, nil, 0, 0)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	case http.MethodPost:
	default:
		s.logTransport(r, requestID, principal, start, http.StatusMethodNotAllowed, "invalid_request", nil, nil, 0, 0)
		writeJSON(w, http.StatusMethodNotAllowed, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32600, Message: "invalid request"},
		})
		return
	}
	if !acceptsMCPPost(r.Header.Get("Accept")) {
		s.logTransport(r, requestID, principal, start, http.StatusNotAcceptable, "invalid_accept_header", nil, nil, 0, 0)
		writeJSON(w, http.StatusNotAcceptable, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32600, Message: "invalid accept header"},
		})
		return
	}

	var raw json.RawMessage
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&raw); err != nil {
		s.logTransport(r, requestID, principal, start, http.StatusBadRequest, "parse_error", nil, nil, 0, 0)
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32700, Message: "parse error"},
		})
		return
	}
	requests, batch, hasRequest, err := decodeRPCRequests(raw)
	if err != nil {
		s.logTransport(r, requestID, principal, start, http.StatusBadRequest, "invalid_request", nil, nil, 0, 0)
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32600, Message: "invalid request"},
		})
		return
	}
	if !hasRequest {
		methods, tools, notifications := summarizeRPCRequests(requests)
		s.logTransport(r, requestID, principal, start, http.StatusAccepted, "accepted_notification", methods, tools, len(requests), notifications)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	methods, tools, notifications := summarizeRPCRequests(requests)
	responses := make([]rpcResponse, 0, len(requests))
	for _, req := range requests {
		resp := s.handle(r.Context(), req)
		if req.ID != nil {
			responses = append(responses, resp)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if batch {
		s.logTransport(r, requestID, principal, start, http.StatusOK, logOutcomeFromResponses(responses), methods, tools, len(requests), notifications)
		writeJSON(w, http.StatusOK, responses)
		return
	}
	if len(responses) == 0 {
		s.logTransport(r, requestID, principal, start, http.StatusAccepted, "accepted_notification", methods, tools, len(requests), notifications)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	s.logTransport(r, requestID, principal, start, http.StatusOK, logOutcomeFromResponses(responses), methods, tools, len(requests), notifications)
	writeJSON(w, http.StatusOK, responses[0])
}

func (s *Server) handle(ctx context.Context, req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo":      map[string]string{"name": "secure-code-retrieval-mcp", "version": "0.1.0"},
				"capabilities":    map[string]any{"tools": map[string]any{}},
			},
		}
	case "tools/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{
					{
						"name":        "code_search_secure",
						"description": "Search enterprise code by keyword or topic and return policy-sanitized snippets. Use this for content search, not for listing repository directories.",
						"inputSchema": searchToolInputSchema(),
					},
					{
						"name":        "code_view_secure",
						"description": "Read a policy-sanitized file window from enterprise code when file_path is already known. If the path is unknown, call code_browse_secure first. start_line must be >= 1 and line_count must be between 1 and 80. Use multiple calls for larger files.",
						"inputSchema": fileViewToolInputSchema(),
					},
					{
						"name":        "code_browse_secure",
						"description": "Browse repository directories and file metadata before reading specific files. This tool returns metadata only, not file contents. Use it to discover paths, then call code_view_secure to read a file and code_search_secure for topic search.",
						"inputSchema": browseToolInputSchema(),
					},
				},
			},
		}
	case "tools/call":
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := decodeParams(req.Params, &params); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "invalid params"}}
		}
		if params.Name != "code_search_secure" && params.Name != "code_view_secure" && params.Name != "code_browse_secure" {
			return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "tool not found"}}
		}
		return s.handleToolCall(ctx, req.ID, params.Name, params.Arguments)
	case "ping":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]string{"status": "ok"}}
	default:
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

func decodeParams(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func acceptsMCPPost(header string) bool {
	header = strings.ToLower(header)
	return strings.Contains(header, "application/json") && strings.Contains(header, "text/event-stream")
}

func decodeRPCRequests(raw json.RawMessage) ([]rpcRequest, bool, bool, error) {
	raw = json.RawMessage(bytesTrimSpace(raw))
	if len(raw) == 0 {
		return nil, false, false, errors.New("empty payload")
	}
	if raw[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, false, false, err
		}
		requests := make([]rpcRequest, 0, len(items))
		hasRequest := false
		for _, item := range items {
			req, isRequest, err := decodeSingleRPCRequest(item)
			if err != nil {
				return nil, true, false, err
			}
			if isRequest {
				hasRequest = true
			}
			requests = append(requests, req)
		}
		return requests, true, hasRequest, nil
	}
	req, isRequest, err := decodeSingleRPCRequest(raw)
	if err != nil {
		return nil, false, false, err
	}
	return []rpcRequest{req}, false, isRequest, nil
}

func decodeSingleRPCRequest(raw json.RawMessage) (rpcRequest, bool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return rpcRequest{}, false, err
	}
	methodRaw, hasMethod := envelope["method"]
	if !hasMethod {
		return rpcRequest{}, false, nil
	}
	var req rpcRequest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return rpcRequest{}, false, err
	}
	_, hasID := envelope["id"]
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil || method == "" {
		return rpcRequest{}, false, errors.New("invalid method")
	}
	if !hasID {
		req.ID = nil
		return req, false, nil
	}
	return req, true, nil
}

func bytesTrimSpace(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

func searchToolInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"source_type", "source_host", "query_text", "max_results", "response_mode"},
		"properties": map[string]any{
			"request_id":     map[string]any{"type": "string"},
			"source_type":    map[string]any{"type": "string", "enum": []string{string(domain.SourceTypeGitHub), string(domain.SourceTypeGitLab)}},
			"source_host":    map[string]any{"type": "string"},
			"query_text":     map[string]any{"type": "string"},
			"max_results":    map[string]any{"type": "integer", "minimum": 1},
			"policy_profile": map[string]any{"type": "string"},
			"response_mode":  map[string]any{"type": "string", "enum": []string{string(domain.ResponseModeSnippet), string(domain.ResponseModeSummary)}},
			"filters": map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"properties": map[string]any{
					"repositories":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"organizations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"groups":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"paths":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"extensions":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"languages":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"page":          map[string]any{"type": "integer", "minimum": 1},
					"per_page":      map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
	}
}

func fileViewToolInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"source_type", "source_host", "repository", "file_path", "ref", "start_line", "line_count"},
		"properties": map[string]any{
			"request_id":     map[string]any{"type": "string"},
			"source_type":    map[string]any{"type": "string", "enum": []string{string(domain.SourceTypeGitHub), string(domain.SourceTypeGitLab)}},
			"source_host":    map[string]any{"type": "string"},
			"repository":     map[string]any{"type": "string"},
			"file_path":      map[string]any{"type": "string"},
			"ref":            map[string]any{"type": "string"},
			"start_line":     map[string]any{"type": "integer", "minimum": 1},
			"line_count":     map[string]any{"type": "integer", "minimum": 1, "maximum": maxFileViewLineCount},
			"policy_profile": map[string]any{"type": "string"},
		},
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func mapMCPError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest), errors.Is(err, domain.ErrMissingPrincipal):
		return -32602, "invalid_request"
	case errors.Is(err, domain.ErrUnauthorized):
		return -32001, "unauthorized"
	case errors.Is(err, domain.ErrForbidden):
		return -32003, "forbidden"
	case errors.Is(err, domain.ErrNotFound):
		return -32004, "not_found"
	case errors.Is(err, domain.ErrUnsupportedFilter):
		return -32022, "unsupported_filter"
	case isConnectorTimeout(err):
		return -32051, "connector_timeout"
	case isConnectorRateLimited(err):
		return -32052, "rate_limited"
	case errors.Is(err, domain.ErrConnector), errors.Is(err, domain.ErrProxyAuth), errors.Is(err, domain.ErrProxyTimeout), errors.Is(err, domain.ErrProxyConnect):
		return -32050, "connector_error"
	case errors.Is(err, domain.ErrPolicyEvaluation):
		return -32060, "policy_error"
	case errors.Is(err, domain.ErrSanitization):
		return -32070, "sanitize_error"
	case errors.Is(err, domain.ErrAuditPersistence):
		return -32080, "audit_error"
	default:
		return -32000, "internal_error"
	}
}

func isConnectorTimeout(err error) bool {
	if errors.Is(err, domain.ErrProxyTimeout) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if !errors.Is(err, domain.ErrConnector) {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

func isConnectorRateLimited(err error) bool {
	if !errors.Is(err, domain.ErrConnector) {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "rate limit") || strings.Contains(text, "rate limited")
}

func (s *Server) handleToolCall(ctx context.Context, id any, name string, arguments json.RawMessage) rpcResponse {
	principal := domain.PrincipalFromContext(ctx)
	roles := domain.RolesFromContext(ctx)
	switch name {
	case "code_search_secure":
		var input gateway.SearchInput
		decoder := json.NewDecoder(strings.NewReader(string(arguments)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "invalid tool arguments"}}
		}
		if input.CallerPrincipal != "" {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "caller_principal must not be supplied"}}
		}
		input.CallerPrincipal = principal
		input.CallerRoles = append([]string(nil), roles...)
		ctx = domain.WithRequestMetadata(ctx, input.RequestID, input.CallerPrincipal, input.CallerRoles)
		resp, err := s.service.Search(ctx, input)
		if err != nil {
			code, payload := mapMCPError(err)
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: payload}}
		}
		return toolSuccessResponse(id, resp)
	case "code_view_secure":
		var input gateway.FileReadInput
		decoder := json.NewDecoder(strings.NewReader(string(arguments)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "invalid tool arguments"}}
		}
		if input.CallerPrincipal != "" {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "caller_principal must not be supplied"}}
		}
		input.CallerPrincipal = principal
		input.CallerRoles = append([]string(nil), roles...)
		ctx = domain.WithRequestMetadata(ctx, input.RequestID, input.CallerPrincipal, input.CallerRoles)
		resp, err := s.service.ReadFileWindow(ctx, input)
		if err != nil {
			code, payload := mapMCPError(err)
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: payload}}
		}
		return toolSuccessResponse(id, resp)
	case "code_browse_secure":
		var input gateway.BrowseInput
		decoder := json.NewDecoder(strings.NewReader(string(arguments)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "invalid tool arguments"}}
		}
		if input.CallerPrincipal != "" {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32602, Message: "caller_principal must not be supplied"}}
		}
		input.CallerPrincipal = principal
		input.CallerRoles = append([]string(nil), roles...)
		ctx = domain.WithRequestMetadata(ctx, input.RequestID, input.CallerPrincipal, input.CallerRoles)
		resp, err := s.service.BrowseRepository(ctx, input)
		if err != nil {
			code, payload := mapMCPError(err)
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: payload}}
		}
		return toolSuccessResponse(id, resp)
	default:
		return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32601, Message: "tool not found"}}
	}
}

func browseToolInputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"source_type", "source_host", "repository"},
		"properties": map[string]any{
			"request_id":     map[string]any{"type": "string"},
			"source_type":    map[string]any{"type": "string", "enum": []string{string(domain.SourceTypeGitHub), string(domain.SourceTypeGitLab)}},
			"source_host":    map[string]any{"type": "string"},
			"repository":     map[string]any{"type": "string"},
			"path":           map[string]any{"type": "string"},
			"ref":            map[string]any{"type": "string"},
			"policy_profile": map[string]any{"type": "string"},
			"depth":          map[string]any{"type": "integer", "minimum": defaultBrowseDepth, "maximum": maxBrowseDepth, "default": defaultBrowseDepth},
			"max_entries":    map[string]any{"type": "integer", "minimum": 1, "maximum": maxBrowseMaxEntries, "default": defaultBrowseMaxEntries},
		},
	}
}

func toolSuccessResponse(id any, payload any) rpcResponse {
	data, _ := json.Marshal(payload)
	return rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"content":           []map[string]string{{"type": "text", "text": string(data)}},
			"structuredContent": payload,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) logTransport(r *http.Request, requestID, principal string, start time.Time, status int, outcome string, methods, tools []string, batchSize, notifications int) {
	if s.logger == nil {
		return
	}
	attrs := []any{
		"request_id", requestID,
		"caller_principal", principal,
		"transport", "http_streamable",
		"http_method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"outcome", outcome,
		"batch", batchSize > 1,
		"batch_size", batchSize,
		"notification_count", notifications,
		"duration_ms", time.Since(start).Milliseconds(),
		"remote_addr", r.RemoteAddr,
	}
	if len(methods) > 0 {
		attrs = append(attrs, "rpc_methods", methods)
	}
	if len(tools) > 0 {
		attrs = append(attrs, "tool_names", tools)
	}
	s.logger.Info("mcp request completed", attrs...)
}

func summarizeRPCRequests(requests []rpcRequest) ([]string, []string, int) {
	methods := make([]string, 0, len(requests))
	tools := make([]string, 0)
	notifications := 0
	for _, req := range requests {
		methods = append(methods, req.Method)
		if req.ID == nil {
			notifications++
		}
		if req.Method == "tools/call" {
			if toolName := extractToolName(req.Params); toolName != "" {
				tools = append(tools, toolName)
			}
		}
	}
	return methods, tools, notifications
}

func extractToolName(raw json.RawMessage) string {
	var params struct {
		Name string `json:"name"`
	}
	if err := decodeParams(raw, &params); err != nil {
		return ""
	}
	return params.Name
}

func logOutcomeFromResponses(responses []rpcResponse) string {
	if len(responses) == 0 {
		return "accepted_notification"
	}
	errorsSeen := 0
	errorCodes := make([]string, 0, len(responses))
	for _, resp := range responses {
		if resp.Error == nil {
			continue
		}
		errorsSeen++
		errorCodes = append(errorCodes, strconv.Itoa(resp.Error.Code))
	}
	switch {
	case errorsSeen == 0:
		return "ok"
	case errorsSeen == len(responses):
		return "rpc_error:" + strings.Join(errorCodes, ",")
	default:
		return "partial_rpc_error:" + strings.Join(errorCodes, ",")
	}
}
