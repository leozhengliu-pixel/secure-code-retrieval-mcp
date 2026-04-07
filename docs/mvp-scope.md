# MVP Scope

## 1. MVP Goal

Deliver a production-shaped pilot that proves enterprises can safely retrieve useful code snippets for AI workflows from GitHub and GitLab without exposing raw code outside approved policy boundaries.

Success means:

- a customer can deploy the service privately
- connect at least one GitHub or GitLab host
- issue MCP code search requests
- receive sanitized snippets with audit records
- validate that the output is useful enough for downstream AI assistance

## 2. What v1 Must Include

### Source connectors

- GitHub Enterprise Cloud support
- GitHub Enterprise Server support
- GitLab Self-Managed support
- GitLab.com project/group support if it does not materially complicate auth

### Search capability

- keyword query
- exact string query where supported
- repo / org / group scoping
- path / extension / language filters where supported
- pagination and top-N limit handling

### Output model

- snippet-level results only by default
- source metadata attached to each snippet
- explicit signal whether content was masked, rewritten, or suppressed

### Redaction and policy

- deterministic rule engine
- policy packs scoped by tenant
- repo / path allowlist and denylist
- regex and literal content masking
- whole-result suppression when policy requires it

### Optional model sanitization

- one OpenAI-compatible provider adapter
- one Anthropic-compatible provider adapter
- timeout and fallback behavior
- post-model validation before response release

### Audit

- request ID and user identity
- source host and connector used
- queried scope
- matched repositories / projects
- policy pack and rule hits
- whether model sanitization was invoked
- final release action per snippet

### Admin configuration

- connector setup through config file or admin API
- policy pack registration
- model endpoint registration
- secret references via environment variables or secret manager integration

### MCP interface

Provide one primary tool in MVP:

- `code_search_secure`

Tool behavior:

- accepts query text, source selector, scope filters, result limit, and response mode
- returns sanitized snippets plus metadata and audit reference

## 3. Explicitly Out of Scope for MVP

- Building or maintaining a custom search index
- Semantic search / embedding retrieval
- Full-file retrieval as the default behavior
- IDE plugins
- End-user web UI beyond a minimal admin/testing surface
- Workflow automation or ticket/document enrichment
- Multi-tenant public SaaS control plane
- Advanced policy authoring UI
- Cross-source ranking optimization beyond basic normalization
- Fine-grained entitlement sync beyond what is required to preserve source access assumptions

## 4. Delivery Plan

### Milestone 1: skeleton and connectors

- initialize core service and MCP server
- implement normalized search request / response schema
- implement one GitHub connector
- implement one GitLab connector
- verify search result normalization

### Milestone 2: deterministic redaction

- implement policy pack format
- implement content and metadata rules
- add suppression and masking actions
- return policy annotations in response

### Milestone 3: audit and deployment hardening

- persist audit records
- add structured logs and tracing
- add connector and model configuration support
- add private deployment documentation

### Milestone 4: model-assisted sanitization

- add provider adapter abstraction
- integrate one OpenAI-compatible endpoint
- integrate one Anthropic-compatible endpoint
- add timeout, retry, and post-validation behavior

### Milestone 5: design-partner validation

- run real retrieval scenarios
- measure usefulness vs over-redaction
- tune policy packs and response schema

## 5. Acceptance Criteria

### Functional

- A caller can search code through MCP against at least one GitHub host and one GitLab host.
- The system returns only sanitized snippets, never raw unrestricted output when policy forbids it.
- Audit records can reconstruct the request and response decision path.
- The service supports customer-provided endpoint config for OpenAI-compatible and Anthropic-compatible models.

### Security

- Requests without valid tenant or policy context are rejected.
- Snippets matching deny rules are suppressed or masked before release.
- No raw snippet text is emitted to model providers when policy marks it non-exportable.
- General service logs do not contain unrestricted raw code payloads.

### Operability

- The service can be deployed in a customer-controlled private environment.
- Connector failures and rate limits are visible in telemetry.
- Policy version used for each request is traceable.

## 6. Suggested Initial Repository Layout

```text
cmd/server
internal/mcp
internal/gateway
internal/connectors/github
internal/connectors/gitlab
internal/policy
internal/sanitize
internal/audit
docs/
```

## 7. Open Questions to Validate During MVP

- How much snippet fidelity is required before AI assistance remains useful?
- Which classes of identifiers should be masked versus generalized versus fully suppressed?
- Do target customers require end-user delegated identity, or is service-brokered access enough for phase 1?
- Are GitHub and GitLab native search results stable enough for target use cases, or does a later custom index become necessary?

## 8. Recommended MVP Thesis

The MVP should prove one specific claim:

An enterprise can safely expose private code search to MCP and AI clients by reusing existing code-host search, enforcing deterministic policy controls, optionally applying private-model sanitization, and keeping the full flow inside customer-controlled infrastructure.
