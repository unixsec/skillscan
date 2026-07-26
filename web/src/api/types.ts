// Shared response shapes (coding spec §9) - mirrors what each router
// actually returns, not the full ORM/domain model.

export interface Session {
  subject: string
  roles: string[]
  tier: string
}

export interface ScanSummary {
  scan_id: string
  state: string
  submitter: string
  content_hash: string
  verdict: string | null
  score: number | null
  is_safe: boolean | null
  skill_id: string | null
  skill_name: string | null
}

export interface ScanDetail {
  scan_id: string
  state: string
  submitter: string
  verdict: string | null
  severity: number | null
  score: number | null
  is_safe: boolean | null
  findings: Finding[]
  provenance: string[][]
  required_ok: boolean | null
  hard_gate_hits: string[]
  reasons: string[]
  sarif_ref: string | null
}

export interface Finding {
  rule_id: string
  test_item_id: string
  category: string
  title: string
  severity: number
  confidence: number
  source_engine: string
  source_capability: string
  trifecta_signals: string[]
  file_path: string | null
  start_line: number | null
  snippet_hash: string | null
  evidence_redacted: string
}

export interface ReviewScan {
  scan_id: string
  content_hash: string
  verdict: string
  reasons: string[]
  issued_at: string
  skill_id: string | null
  submitter: string | null
}

export interface AllowlistEntry {
  id?: string
  scope_type: string
  scope_value: string
  resolved_skill_id?: string | null
  rule_id: string
  expires_at: string
  approved_by: string
  requested_by: string
  reason: string
}

export interface AllowlistSkillCandidate {
  skill_id: string
  content_hashes: string[]
}

export interface AllowlistRuleCandidate {
  rule_id: string
  is_hard_gate: boolean
}

export interface AllowlistCandidates {
  skills: AllowlistSkillCandidate[]
  rule_ids: AllowlistRuleCandidate[]
}

export interface InventorySkill {
  skill_id: string
  source: string
  trust_tier: string
  state: string | null
}

export interface InventoryDetail extends InventorySkill {
  versions: { content_hash: string; toolchain_digest: string; created_at: string }[]
  baseline: { content_hash: string; approved_at: string } | null
}

export interface ReevalSkill {
  skill_id: string
  trust_tier: string
  content_hash: string
  recorded_toolchain_digest: string
  stale: boolean
}

export interface DriftSkillStatus {
  skill_id: string
  baseline_content_hash: string
  latest_content_hash: string | null
  drifted: boolean
}

export interface DriftEvent {
  skill_id: string
  content_hash: string | null
  occurred_at: string
  reason: string
}

export interface DriftSummary {
  skills: DriftSkillStatus[]
  events: DriftEvent[]
}

export interface ReconciliationOutcome {
  content_hash: string | null
  skill_id: string | null
  result: string
  source: string
  detected_at: string
}

export interface AuditEntrySummary {
  seq: number
  operator: string
  action: string
  payload: Record<string, unknown>
  chained_at: string
}

export interface Report {
  template: string
  since: string | null
  until: string | null
  summary: Record<string, unknown>
  rows: Record<string, unknown>[]
}

export interface ReportSchedule {
  id: number
  template: string
  cron: string
  targets: string[]
  created_by: string
  created_at: string
}

export interface EngineInfo {
  name: string
  version: string | null
  required: boolean
  enabled: boolean
  capabilities: string[]
}

export interface PolicyProposal {
  id: number
  changes_hard_gate_rules: boolean
  status: string
  proposed_by: string
  approved_by: string | null
  reason: string | null
  created_at: string
  decided_at: string | null
}

export interface ActivePolicy {
  version: string
  required_engines: string[]
  hard_gate_rules: string[]
  review_confidence: number
  block_on_severity: string
  review_on_severity: string
}

export interface PolicyStatus {
  active_policy: ActivePolicy
  pending_proposals: PolicyProposal[]
}

export interface IntelSourceSummary {
  source: string
  indicator_count: number
  last_imported_at: string | null
}

export interface BreakGlassStatus {
  enabled: boolean
  armed: boolean
}

export interface LocalAccount {
  id: number
  username: string
  role: string
  status: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface GroupRoleMapping {
  group_name: string
  role: string
}
