CREATE TABLE IF NOT EXISTS schema_migrations (
  version BIGINT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_requests (
  audit_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  caller_principal TEXT NOT NULL,
  caller_roles_json JSONB NOT NULL,
  source_type TEXT NOT NULL,
  source_host TEXT NOT NULL,
  query_text TEXT NOT NULL,
  filters_json JSONB NOT NULL,
  policy_profile TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_decisions (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT NOT NULL,
  audit_id TEXT NOT NULL,
  evidence_id TEXT NOT NULL,
  repository TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_start INT NOT NULL,
  line_end INT NOT NULL,
  decision TEXT NOT NULL,
  matched_rules JSONB NOT NULL,
  model_invoked BOOLEAN NOT NULL,
  release_mode TEXT NOT NULL,
  suppression_reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_deliveries (
  audit_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  snippet_count INT NOT NULL,
  raw_hit_count INT NOT NULL,
  evidence_count INT NOT NULL,
  suppressed_count INT NOT NULL,
  response_bytes INT NOT NULL,
  connector_stats JSONB NOT NULL,
  latency_millis BIGINT NOT NULL,
  results_truncated BOOLEAN NOT NULL,
  suppressed_due_to_budget INT NOT NULL,
  remaining_hits_estimate INT NOT NULL,
  summary_generated BOOLEAN NOT NULL,
  summary_citation_ids JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_requests_caller_principal ON audit_requests (caller_principal);
CREATE INDEX IF NOT EXISTS idx_audit_decisions_request_id ON audit_decisions (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_decisions_audit_id ON audit_decisions (audit_id);
CREATE INDEX IF NOT EXISTS idx_audit_deliveries_request_id ON audit_deliveries (request_id);
