# Task Breakdown

## 1. Delivery Strategy

Split the work into six workstreams that can progress mostly in parallel once the repository skeleton exists:

- foundation
- connector integration
- policy and sanitization
- audit and storage
- MCP surface
- deployment and operations

The first implementation target is a private-deployment pilot, not a broadly packaged product.

## 2. Workstream A: Foundation

### Goal

Create the Go service skeleton and the shared runtime primitives.

### Tasks

1. Initialize Go module and repository layout.
2. Add application bootstrap, config loading, and structured logging.
3. Define core domain types for requests, results, policy decisions, and audit records.
4. Add context propagation, timeout configuration, and error model.
5. Add health and readiness endpoints.

### Done criteria

- Service starts locally with config validation
- package layout is stable enough for feature work
- core types compile and are shared by downstream modules

## 3. Workstream B: Connector Integration

### Goal

Support native search retrieval from GitHub and GitLab.

### Tasks

1. Implement normalized search request compiler for GitHub.
2. Implement GitHub search client and result normalization.
3. Implement normalized search request compiler for GitLab.
4. Implement GitLab search client and result normalization.
5. Add connector auth handling for cloud and self-managed hosts.
6. Add pagination, timeout, retry, and rate-limit handling.
7. Add connector contract tests using captured fixtures or mocked responses.

### Done criteria

- one GitHub host and one GitLab host can be queried through the same internal service contract
- normalized result schema is stable
- connector failures are surfaced in a controlled way

## 4. Workstream C: Policy and Sanitization

### Goal

Guarantee that unsafe output never leaves the gateway unprocessed.

### Tasks

1. Define policy pack format and validation rules.
2. Implement repository, path, and metadata-based rule evaluation.
3. Implement deterministic content masking and suppression.
4. Implement response validator for post-transform checks.
5. Add model-assisted sanitization adapter interface.
6. Add OpenAI-compatible provider integration.
7. Add Anthropic-compatible provider integration.
8. Add fallback rules when model sanitization is unavailable or times out.

### Done criteria

- deterministic policy evaluation works without model dependency
- model-assisted sanitization is optional and bounded by policy
- unsafe snippets are suppressed or transformed according to policy

## 5. Workstream D: Audit and Storage

### Goal

Make every retrieval explainable and traceable.

### Tasks

1. Define audit entity model.
2. Create PostgreSQL schema and migration plan.
3. Implement persistence for request, decision, and delivery records.
4. Add request ID propagation through the whole service.
5. Add audit retrieval API by request ID.
6. Add retention and payload minimization rules for sensitive fields.

### Done criteria

- every served response has an audit ID
- request path can be reconstructed from audit records
- raw payload retention follows the design constraints

## 6. Workstream E: MCP Surface

### Goal

Expose the secure retrieval capability to AI clients in a stable way.

### Tasks

1. Define MCP tool schema for `code_search_secure`.
2. Implement MCP server bootstrap.
3. Map MCP tool inputs into gateway requests.
4. Shape sanitized gateway responses into MCP output.
5. Add input validation and caller-facing error responses.
6. Add integration tests for end-to-end MCP search flow.

### Done criteria

- MCP client can call `code_search_secure`
- response contains sanitized snippets and audit metadata
- errors are stable and machine-usable

## 7. Workstream F: Deployment and Operations

### Goal

Make the service installable and operable in enterprise environments.

### Tasks

1. Add container build and runtime configuration.
2. Add deployment examples for local Docker and Kubernetes.
3. Add observability wiring for logs, metrics, and tracing.
4. Add secure secret-loading patterns.
5. Add custom CA and self-managed host configuration support.
6. Add operational runbook and troubleshooting notes.

### Done criteria

- service can run in a containerized private environment
- operators can inspect health, latency, and connector failures
- self-managed GitHub and GitLab host connectivity is documented

## 8. Suggested Build Order

### Phase 1

- foundation
- connector integration

### Phase 2

- policy and sanitization
- audit and storage

### Phase 3

- MCP surface
- deployment and operations

### Phase 4

- design partner hardening
- latency tuning
- policy tuning based on real snippets

## 9. Task Ownership Suggestion

If multiple engineers are involved, split work like this:

- Engineer 1: foundation plus gateway core
- Engineer 2: GitHub and GitLab connectors
- Engineer 3: policy, sanitization, and model adapters
- Engineer 4: audit, storage, and deployment hardening

For a single engineer, phase-based execution is better than component parallelism.

## 10. Risks to Track During Execution

- GitHub and GitLab result formats may require more normalization work than expected.
- Redaction can become too destructive and reduce downstream AI usefulness.
- Model-assisted sanitization may increase latency beyond acceptable bounds.
- Self-managed host authentication and TLS edge cases can dominate integration time.

## 11. Definition of MVP Complete

MVP is complete when all of the following are true:

1. A private deployment can connect to at least one GitHub instance and one GitLab instance.
2. MCP clients can request secure code search and receive sanitized snippets.
3. Deterministic redaction is enforced before any optional model processing.
4. Audit records exist for every request and can be retrieved by request ID.
5. The system is usable by a design partner without source code leaving approved boundaries in raw form.
