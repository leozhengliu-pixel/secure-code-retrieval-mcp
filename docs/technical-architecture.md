# Technical Architecture

## 1. Architecture Goal

Provide a policy-enforcing retrieval layer between enterprise code hosts and downstream MCP or API consumers without copying or reindexing the source code corpus in v1.

## 2. High-Level System

### Core components

1. MCP Server
   Exposes tools for code search and secure snippet retrieval to AI clients.
2. Gateway API
   Internal service layer that validates requests, enforces authn/authz, and orchestrates retrieval.
3. Connector Layer
   Adapters for GitHub Enterprise and GitLab, including cloud and self-managed hosts.
4. Policy Engine
   Deterministic evaluation of redaction rules and response controls.
5. Sanitization Engine
   Applies deterministic transforms first, then optional model-assisted rewrite.
6. LLM Provider Adapters
   Support OpenAI-compatible and Anthropic-compatible endpoints.
7. Audit Pipeline
   Writes request, decision, and response metadata to durable storage.
8. Admin Configuration Store
   Stores connector definitions, policy packs, model configs, and deployment settings.

### Request flow

1. Caller invokes MCP tool or API with query, filters, user identity, and tenant context.
2. Gateway authenticates caller and resolves customer policy context.
3. Gateway determines source connector and validates repository or org scope.
4. Connector executes native search through GitHub or GitLab.
5. Gateway normalizes platform-specific results into a common snippet schema.
6. Policy engine evaluates rules against raw snippet payload and metadata.
7. Sanitization engine applies masking, replacement, truncation, or suppression.
8. If configured, model-assisted sanitization rewrites the already policy-bounded snippet.
9. Response builder returns sanitized snippets, policy annotations, and audit reference.
10. Audit pipeline records the full decision trail.

## 3. Major Technical Decisions

### Search strategy

Use source-platform-native search instead of maintaining a custom index in v1.

Reasoning:

- Lower implementation cost
- Faster path to deployment
- Better compatibility with customer trust expectations
- Avoids duplicating code storage in another system

Tradeoff:

- Less control over ranking and recall
- Platform inconsistencies must be normalized

### Retrieval granularity

Return snippet-level results, not full files, by default.

Reasoning:

- Lowers leakage risk
- Reduces payload size and model context cost
- Better aligns with “minimum necessary disclosure”

### Identity model

Prefer end-user attributable requests, even when a service credential performs the source query.

Requirements:

- Every request must carry a user principal or traceable system identity
- Audit records must preserve both the initiating identity and execution credential

### Redaction precedence

Deterministic policies must run before any LLM call.

Pipeline:

1. classify result metadata
2. apply deny / allow / suppress decisions
3. mask deterministic patterns
4. optionally run model rewrite on the already bounded content
5. post-validate output before release

### Failure behavior

Fail closed for:

- connector trust failure
- missing or invalid policy context
- sanitization validation failure
- unsupported source behavior when the policy requires stronger controls

## 4. Service Boundaries

### MCP Server

Responsibilities:

- Expose stable tool contracts
- Map tool calls to gateway requests
- Enforce caller-facing limits and pagination
- Return structured metadata for downstream agent behavior

Suggested tools:

- `code_search_secure`
- `code_search_preview`
- `policy_explain`

### Gateway API

Responsibilities:

- Authentication and authorization
- Connector routing
- Response orchestration
- Rate limiting
- tenant isolation
- policy lookup

Suggested internal APIs:

- `POST /v1/search`
- `POST /v1/policies/evaluate`
- `GET /v1/audit/{request_id}`

### Connector layer

Responsibilities:

- Auth to GitHub or GitLab hosts
- Query compilation from normalized search request to platform syntax
- Result normalization
- pagination and rate-limit handling
- self-managed TLS and hostname support

Connector-specific notes:

- GitHub connector should support both `gh` CLI-backed execution and direct API mode, but API mode should be the primary production path.
- GitLab connector should support both `glab` CLI-backed execution and direct API mode, with API mode preferred for deterministic service behavior.
- CLI mode is valuable for local debugging and bootstrap, not as the long-term core service dependency.

### Policy engine

Responsibilities:

- Rule loading and validation
- Pattern matching on content and metadata
- path and repo-level restrictions
- severity classification
- release decision and transform plan generation

Suggested policy dimensions:

- source scope rules
- content pattern rules
- identity-based rules
- environment-based rules
- output shape rules

### Sanitization engine

Deterministic transforms:

- token masking
- literal replacement
- comment removal
- line suppression
- block suppression
- placeholder generalization

Model-assisted transforms:

- rewrite to abstracted pseudocode
- summarize unsafe logic instead of returning literal code
- replace internal identifiers with neutral placeholders

### Audit pipeline

Write two classes of records:

- Decision record: request, scope, policy version, model settings, release decision
- Delivery record: response size, snippet count, caller, latency, connector result stats

Recommended storage:

- PostgreSQL for relational audit and config data
- Object storage for immutable decision artifacts if large payload retention is required

## 5. Data Model

### Normalized search request

- tenant_id
- request_id
- caller_principal
- source_type
- source_host
- query_text
- search_mode
- scope_filters
- max_results
- policy_profile
- response_mode

### Normalized search result

- source_type
- source_host
- repo_or_project
- file_path
- ref
- language
- snippet_text_raw
- match_ranges
- source_url
- permissions_context

### Sanitized response item

- snippet_text_sanitized
- redaction_actions
- suppression_reason
- confidence
- release_mode

## 6. Deployment Model

### Default deployment

- Kubernetes service
- Internal ingress only
- Customer-managed secrets
- Private egress allowlist to code hosts and model endpoints

### Required external dependencies

- GitHub Enterprise / GitHub Enterprise Server or GitLab instance
- Postgres
- Secret manager
- Customer-approved model endpoint if model-assisted sanitization is enabled

### Security controls

- mTLS or equivalent internal service auth where available
- per-tenant encryption for secrets
- signed audit entries or append-only audit storage
- host allowlist for code and model endpoints
- admin-only connector configuration

## 7. Non-Functional Targets

### Reliability

- Stateless service tier
- idempotent request IDs
- graceful degradation when a source host is rate-limited

### Latency targets

- Search-only path: target p95 under 3 seconds for moderate queries in healthy environments
- Search plus deterministic sanitization: target p95 under 4 seconds
- Search plus model sanitization: target p95 under 8 seconds, with configurable timeout fallback

### Observability

- structured logs
- request tracing
- connector latency metrics
- policy hit metrics
- model invocation metrics
- suppression rate and false-positive review metrics

## 8. Recommended Initial Tech Stack

- Language: Go or TypeScript
- Preferred recommendation: Go for the core gateway and connectors because deployment, concurrency, and enterprise service operation are simpler.
- MCP surface: official MCP server SDK in the chosen language
- Database: PostgreSQL
- Cache: optional Redis only if rate-limit or policy caching becomes necessary
- Policy format: YAML or JSON policy packs stored in Postgres and versioned in git
- Model integration: adapter interface for OpenAI-compatible and Anthropic-compatible chat/completions endpoints

## 9. Security and Compliance Considerations

- Never send raw snippet text to an LLM if policy marks the content as non-exportable.
- Separate connector credentials from caller identity; do not let callers directly control source credentials.
- Log enough detail for review, but do not store unrestricted raw code in general application logs.
- Support configurable retention for audit artifacts and model prompts.
- Ensure self-managed host support includes custom CA bundles and strict hostname pinning options.

## 10. Architecture Recommendation

Build the first implementation as a single deployable service with clear internal modules, not as many microservices.

Reasoning:

- Easier to ship
- Easier to secure
- Lower operational burden for early enterprise pilots
- Still compatible with later extraction of policy or audit subsystems if adoption justifies it
