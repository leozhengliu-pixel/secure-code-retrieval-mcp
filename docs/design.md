# Detailed Design

## 1. Design Goal

Build a Go-based secure code retrieval gateway that exposes MCP tools for enterprise code search, uses GitHub and GitLab native search as the retrieval backend, applies deterministic and optional model-assisted sanitization, and emits a complete audit trail for every request.

## 2. System Shape

The first implementation should be a modular monolith.

Reasons:

- Faster to ship and easier to operate in private customer environments
- Lower coordination overhead than microservices
- Easier to secure, trace, and test end-to-end
- Internal module boundaries can later be extracted if scale or organizational needs justify it

## 3. Runtime Topology

One deployable service contains:

- MCP transport and tool handlers
- Internal HTTP API
- connector adapters
- policy evaluation
- sanitization pipeline
- audit persistence
- configuration loading

External dependencies:

- GitHub Enterprise Cloud or Server
- GitLab.com or Self-Managed
- PostgreSQL
- optional LLM endpoint
- optional secret manager

## 4. Core Request Lifecycle

### Search request path

1. Caller invokes `code_search_secure` through MCP.
2. MCP handler validates the request shape and caller metadata.
3. Gateway resolves tenant, connector, and policy profile.
4. Connector compiles the normalized query into source-platform syntax.
5. Source platform returns native search results.
6. Connector normalizes results into the internal snippet model.
7. Policy engine evaluates metadata and raw snippet content.
8. Sanitization engine applies deterministic transforms.
9. If enabled and allowed, model-assisted sanitization rewrites the already bounded snippet.
10. Response validator confirms output still satisfies policy.
11. Audit records are written.
12. Sanitized results are returned with metadata and an audit ID.

### Failure rules

- If identity or tenant context is missing, reject the request.
- If connector configuration is invalid, fail closed.
- If policy evaluation cannot complete, fail closed.
- If model sanitization fails, fall back to deterministic-only output only when policy permits it.
- If no safe output can be produced, return a suppression result instead of raw content.

## 5. Internal Modules

### `internal/mcp`

Responsibilities:

- expose MCP tool definitions
- validate tool input
- convert MCP calls to gateway requests
- shape gateway responses back into MCP-safe output

Primary tool in v1:

- `code_search_secure`

### `internal/gateway`

Responsibilities:

- request orchestration
- tenant resolution
- connector selection
- policy profile binding
- response assembly
- request timeout management

The gateway package should own the main service contract used by MCP and future HTTP APIs.

### `internal/connectors/github`

Responsibilities:

- query GitHub Enterprise Cloud or Server
- translate normalized filters to GitHub search syntax
- normalize snippet and metadata output
- handle pagination and rate limits

### `internal/connectors/gitlab`

Responsibilities:

- query GitLab.com or Self-Managed search
- translate normalized filters to GitLab API parameters
- normalize result output
- handle pagination and instance-specific differences where possible

### `internal/policy`

Responsibilities:

- load policy packs
- evaluate metadata rules
- evaluate content rules
- determine allow, mask, rewrite, or suppress actions
- emit machine-readable decision data

### `internal/sanitize`

Responsibilities:

- apply deterministic masking and suppression
- run optional model-assisted rewrite
- perform post-sanitization validation

### `internal/audit`

Responsibilities:

- persist audit records
- define audit event schema
- provide retrieval by request ID
- ensure raw content retention is controlled and minimal

### `internal/config`

Responsibilities:

- load application config
- load connector definitions
- load policy references
- load model endpoint definitions
- validate startup configuration

## 6. Primary Data Contracts

### Search request

Fields:

- `tenant_id`
- `caller_principal`
- `source_type`
- `source_host`
- `query_text`
- `filters`
- `max_results`
- `policy_profile`
- `response_mode`

### Normalized result

Fields:

- `repository`
- `file_path`
- `ref`
- `language`
- `snippet_text_raw`
- `match_ranges`
- `source_url`
- `connector_metadata`

### Policy decision

Fields:

- `decision`
- `matched_rules`
- `transforms`
- `export_allowed`
- `model_allowed`

### Sanitized result

Fields:

- `snippet_text`
- `release_mode`
- `redaction_actions`
- `suppression_reason`
- `audit_id`

## 7. Connector Strategy

### Production mode

Prefer direct API integration for GitHub and GitLab.

Reasons:

- deterministic service behavior
- easier error handling
- clearer auth and rate-limit control
- no shell dependency in production

### Diagnostic mode

Retain optional CLI-backed diagnostic helpers for local debugging:

- `gh`
- `glab`

These should not be required for normal server operation.

## 8. Policy and Sanitization Design

### Policy precedence

Rule evaluation order:

1. source scope restrictions
2. path and repository restrictions
3. content deny rules
4. deterministic masking rules
5. model eligibility check
6. post-model validation

### Rule classes

- deny rule
- suppress rule
- mask rule
- rewrite-required rule
- metadata classification rule

### Model-assisted sanitization constraints

- model input must already be policy-bounded
- model usage must be explicitly enabled per tenant or policy profile
- model output must be revalidated
- raw snippet content marked non-exportable must never be sent to a model

## 9. Persistence Design

### PostgreSQL tables to expect

- `tenants`
- `connectors`
- `policy_profiles`
- `policy_versions`
- `model_endpoints`
- `audit_requests`
- `audit_decisions`
- `audit_deliveries`

The exact schema can be refined later, but these logical entities should remain stable.

## 10. Observability Design

Required telemetry:

- request count and latency
- connector latency and error rate
- policy hit counts by rule and action
- sanitization mode usage
- suppression rate
- model call latency and failures
- source-host rate-limit events

Tracing should cover:

- request entry
- connector search
- policy evaluation
- model sanitization
- audit persistence

## 11. Security Design Rules

- No unrestricted raw snippet text in standard logs.
- Secrets must not be stored in plain config files in production.
- All external hosts must be allowlisted.
- Tenant context must be explicit on every request.
- Connector credentials must be isolated from caller identity.
- The service should support custom CA bundles for self-managed hosts.

## 12. Go Implementation Guidance

Recommended package direction:

- keep domain types small and explicit
- use `context.Context` through every request path
- enforce timeouts at connector and model boundaries
- avoid hidden global state
- keep interfaces near consumers, not only near implementations

Recommended first code layout:

```text
cmd/server
internal/app
internal/mcp
internal/gateway
internal/connectors/github
internal/connectors/gitlab
internal/policy
internal/sanitize
internal/audit
internal/config
internal/storage/postgres
```

## 13. Design Decisions Already Locked

- Core language is Go.
- Deployment model is private customer-controlled infrastructure.
- Architecture is a modular monolith for v1.
- Source retrieval uses GitHub and GitLab native search, not a custom index.
- Deterministic policy controls take precedence over LLM rewriting.
- Default response unit is a snippet, not a full file.
