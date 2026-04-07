# Product Plan

## 1. Product Definition

### Working name

Secure Code Retrieval MCP Gateway

### One-line positioning

An enterprise-grade private deployment gateway that lets AI tools and MCP clients search private code in GitHub Enterprise and GitLab, then receive policy-compliant redacted snippets instead of raw source.

### Core problem

Enterprises increasingly want AI agents to work with private code, but existing options leave a gap:

- Native platform search can find code, but does not provide enterprise policy enforcement for AI-ready snippet output.
- Enterprises do not want raw proprietary code leaving approved trust boundaries.
- Security and compliance teams need auditable proof of who retrieved which code, under which policy, and what transformations were applied.
- Many customers already have self-hosted or approved LLM gateways and cannot depend on public SaaS-only workflows.

### Core value proposition

The product does not compete by building a better code search engine. It competes by becoming the secure control plane between enterprise code hosts and AI consumers.

Primary value:

- Reuse native GitHub and GitLab search capabilities
- Preserve source-platform permissions
- Apply rule-based and model-based redaction to snippets
- Emit auditable retrieval and redaction records
- Support customer-controlled private deployment and model endpoints

## 2. Target Customer

### Primary customer profile

High-compliance enterprises with large internal codebases:

- Financial services
- Government and regulated public sector
- Healthcare and biotech
- Semiconductors and industrial technology
- Large multinational engineering organizations with strict IP controls

### Buying center

- Platform engineering
- Security engineering
- AI platform / internal developer tooling
- Compliance / governance stakeholders as approvers

### Ideal early adopter

A company that already has:

- GitHub Enterprise Cloud, GitHub Enterprise Server, GitLab.com group, or GitLab Self-Managed
- Internal demand for MCP or AI developer assistants
- An approved internal LLM endpoint or gateway
- Concern about code exfiltration, prompt leakage, or raw source exposure

## 3. Product Shape

### Delivery model

Private deployment gateway inside customer-controlled infrastructure.

Recommended deployment options:

- Kubernetes in customer VPC / data center
- Single-tenant VM deployment for early pilots
- No shared multi-tenant SaaS in v1

### Primary interface

An MCP server plus internal service APIs.

External behavior:

- MCP clients issue search requests with user context and query constraints
- Gateway queries GitHub or GitLab using customer credentials or brokered service credentials
- Gateway receives search results and snippet metadata
- Gateway applies enterprise redaction policies
- Gateway optionally invokes a customer-approved LLM for secondary sanitization
- Gateway returns safe snippets plus explanation metadata and audit identifiers

## 4. Why This Has Value

### Market logic

This product addresses a real gap between code search and safe AI usage. Enterprises already pay for:

- Sourcegraph / Glean / internal search tooling
- AI gateways
- DLP / governance controls

The gap is a narrow but important layer: permission-aware code retrieval with AI-safe output controls.

### Why customers would buy

- They want internal AI to use private code without exposing raw source unnecessarily.
- They need stronger controls than a local desktop plugin can provide.
- They want a deployment model that keeps code, logs, and model traffic inside approved boundaries.
- They need auditability for security reviews and internal compliance.

### Why this should not be pitched as “code search”

If positioned as search, the product is weak against native GitHub/GitLab search, Sourcegraph, and Glean.

If positioned as secure AI code-context infrastructure, the differentiation is stronger:

- Redaction and output control
- Policy enforcement before snippets leave the trust boundary
- Deployment in customer environment
- Standard MCP interface for downstream tools

## 5. Product Principles

- Source platform remains the system of record for code and permissions.
- Default output is the minimum code necessary to satisfy the request.
- Rule-based policy decisions always take precedence over model suggestions.
- Every retrieval must be attributable to a user, policy set, and request ID.
- The product must support “private AI only” organizations.
- The product must fail closed when policy evaluation or connector trust cannot be established.

## 6. Capability Model

### A. Unified enterprise code retrieval

Support:

- GitHub Enterprise Cloud
- GitHub Enterprise Server
- GitLab.com groups/projects
- GitLab Self-Managed

Search modes for v1:

- Keyword search
- Exact string search where supported
- Regex search where supported by source platform
- Filters by repository, org/group, path, file extension, and language where source platform supports them

### B. Policy-driven redaction

Rule packs define content that must not be emitted in raw form.

Example policy targets:

- Secrets and credentials
- Access keys and tokens
- Internal URLs and hostnames
- Tenant identifiers
- Customer names or IDs
- Internal service names
- PII patterns
- Protected comments or compliance markers
- Source paths classified as restricted

### C. Model-assisted sanitization

Optional second-pass processing via customer-approved LLM.

Use cases:

- Generalizing business-specific identifiers
- Rewriting code comments that reveal internal context
- Abstracting implementation-specific details while preserving logic shape
- Removing data not covered by deterministic regex or rule engines

### D. Audit and governance

The product stores an immutable audit trail for:

- Request identity
- Source system queried
- Search terms and filters
- Repositories touched
- Policy decisions applied
- Model usage
- Redaction actions taken
- Response class and snippet count

### E. MCP-native consumption

This is not just an API service. It should be easy for MCP-capable tools to consume as a trusted code retrieval source.

## 7. Packaging Strategy

### Phase 1

Pilot with one or two design partners in private deployment form.

### Phase 2

Harden for broader enterprise rollout:

- HA deployment
- richer RBAC
- admin UI
- policy pack lifecycle
- more connectors

### Pricing logic

Best aligned packaging dimensions:

- Per connected code host / connector
- Per protected developer seat or active MCP client
- Premium for advanced redaction and governance
- Additional premium for private support / regulated deployment

Avoid commodity search pricing.

## 8. Risks

### Product risks

- Customers may prefer broader platforms like Glean or Sourcegraph if your value proposition is not sharply security-focused.
- Redaction quality may be too destructive or too weak if policy design is poor.
- Buyers may classify this as “yet another AI gateway feature” unless the code-specific control story is strong.

### Execution risks

- GitHub and GitLab search semantics differ materially.
- Self-managed customer environments vary widely in auth, network, and certificate setup.
- Model-assisted sanitization can add latency and non-determinism.

### Mitigation

- Lead with high-compliance use cases.
- Keep source search native; do not build your own index in v1.
- Make deterministic policy redaction the primary mechanism.
- Limit model usage to clearly bounded second-pass sanitization.

## 9. Go / No-Go Recommendation

### Recommendation

Go, with a narrow thesis:

Build a private-deployment secure code retrieval gateway for AI and MCP, not a general code search product.

### Conditions for continued investment

- Confirm at least two enterprise design partners with real governance needs
- Validate that snippet-level redaction still preserves enough utility for AI workflows
- Prove that GitHub and GitLab connectors can deliver acceptable latency and result quality in target environments
