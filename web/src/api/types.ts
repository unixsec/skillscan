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
  // The FIRST submitter only (`ScanJob.submitter`). Kept for compatibility -
  // `submitters` below is the authoritative list. Prefer `submitterNames()`
  // over reading either directly.
  submitter: string
  content_hash: string
  verdict: string | null
  score: number | null
  is_safe: boolean | null
  skill_id: string | null
  skill_name: string | null
  // 里程碑 F Task 16: the same attribution shape `ScanDetail` carries, on the
  // LIST too. Until this task the list had only the scalar above, so a
  // deduplicated scan showed a stranger's name in the table and the right names
  // one click away in the drawer. Optional in the TYPE only, so a response from
  // a backend that predates the change still parses; the current backend always
  // sends all three.
  submitters?: string[]
  source?: string[]
  submitter_sources?: SubmitterSource[]
}

// Every rightful submitter of a scan, best available source first. The two
// fallbacks are for a backend that predates 里程碑 F Task 16 and are never used
// to invent data - an empty result means nothing was recorded, which callers
// render as absence rather than as a guess.
//
// Shared by the scan list and the review queue precisely because one concept
// with two renderings is the bug this task exists to remove.
export function submitterNames(scan: {
  submitter?: string | null
  submitters?: string[]
}): string[] {
  if (scan.submitters?.length) return scan.submitters
  return scan.submitter ? [scan.submitter] : []
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
  // 里程碑 F Task 14: two DIFFERENT facts, no longer one column read twice.
  // `trust_tier` is the tier THIS caller asked for (their own scan_submitter
  // row); `judged_at_tier` is the tier the verdict was actually adjudicated at
  // (`ScanJob.trust_tier`). They diverge when single-flight dedup hands a later
  // submitter someone else's verdict, which is never re-adjudicated.
  //
  // When this caller has no recorded request - a reviewer reading someone
  // else's scan, or a row written before the backend column existed - the
  // backend returns the judged tier for both, so they compare equal and nothing
  // is flagged. Per-name truth, including "no request recorded", is in
  // `submitter_sources`.
  trust_tier: string | null
  judged_at_tier: string | null
  // Which way a divergence cuts, computed server-side from the gate policy's
  // real block thresholds - never from the declaration order of the tier names,
  // which is not what determines strictness.
  //
  // 'looser' is the case that matters: the verdict was reached under a MORE
  // PERMISSIVE ruleset than this caller asked for, so a finding that should have
  // blocked for them can read PASS. 'stricter' is the safe side (possible
  // over-blocking). 'equivalent' means the names differ but the policy treats
  // them identically. `null` means no comparison was possible.
  tier_direction: 'looser' | 'stricter' | 'equivalent' | null
  // WHICH policy `tier_direction` was computed under. Strictness lives in the
  // policy's `tier_block_overrides`, so a policy approved between signing and
  // viewing can relabel a historical verdict - showing a divergence that did
  // not exist when the adjudication happened, or hiding one that did.
  //
  // 'signing_policy' - the verdict's own policy_version is the one the server
  // has loaded, so the direction describes the adjudication as it happened.
  // 'current_policy' - it does not, or no verdict has been signed yet. The
  // direction is still the best available reading, but it describes TODAY's
  // thresholds and the page says so. `null` whenever `tier_direction` is.
  //
  // The server deliberately does NOT reconstruct the historical policy to give
  // a "true" answer: only `verdict.policy_version` is recoverable, not the
  // thresholds that version carried. See gate/policy.py's `tier_divergence`.
  tier_direction_basis: 'signing_policy' | 'current_policy' | null
  // Always a list, even for exactly one submitter - never a bare string.
  submitters: string[]
  // 里程碑 F Task 12: the channels this scan arrived through ("console" /
  // "marketplace"), sorted and deduplicated.
  //
  // A LIST, not a single value: one scan legitimately has several submitters
  // (submissions of identical content collapse onto one scan_job), so the
  // console and the marketplace submitting the same skill is the normal case -
  // a scalar would silently drop one of the two channels exactly then.
  // Empty means no submitter row on this scan records a channel (rows written
  // before the backend column existed); it is never filled in with a guess.
  source: string[]
  // Which submitter arrived through which channel - the per-name attribution
  // behind `source`. `source: null` on an entry means that row records no
  // channel; it is passed through verbatim rather than defaulted.
  submitter_sources: SubmitterSource[]
}

export interface SubmitterSource {
  submitter: string
  source: string | null
  // 里程碑 F Task 14: the trust tier this particular submitter asked for. `null`
  // means their row records no request (written before the backend column
  // existed) and is rendered as unknown - never filled in from the scan's judged
  // tier, which would assert the agreement the field exists to stop assuming.
  requested_trust_tier: string | null
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
  // The FIRST submitter only. See `ScanSummary.submitter`; use
  // `submitterNames()` rather than reading this directly.
  submitter: string | null
  // I3: the skill has already moved past the content this entry covers (a
  // newer version was submitted, or an admin retired/quarantined it), so a
  // decision on it would be discarded by the lifecycle worker. Server-side
  // fact, not a frontend inference - the API refuses the decision too.
  superseded: boolean
  // 里程碑 F Task 16: identical attribution shape to `ScanSummary` and
  // `ScanDetail`. It matters more here than on the scan list: SoD forbids
  // approving a scan you submitted, and a queue showing one name out of several
  // could offer an approver a decision the API will refuse.
  submitters?: string[]
  source?: string[]
  submitter_sources?: SubmitterSource[]
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
  // 里程碑 F Task 15: who may submit a new version of this skill. `null` means
  // no owner is on record, which FAILS CLOSED - only an admin can submit it -
  // and is the state every skill registered before the column existed is in.
  // Never guessed at from the genesis actor; see UnownedSkill below.
  owner: string | null
}

export interface InventoryDetail extends InventorySkill {
  versions: { content_hash: string; toolchain_digest: string; created_at: string }[]
  baseline: { content_hash: string; approved_at: string } | null
}

export interface UnownedSkill {
  skill_id: string
  source: string
  trust_tier: string
  state: string | null
  // ADVISORY ONLY: the identity recorded on this skill's genesis lifecycle
  // event, i.e. who first submitted it. Shown so an admin can decide an
  // assignment with the evidence in front of them - never auto-applied, by
  // this console or by anything else. "Who submitted this once" and "who may
  // modify it now" are different questions. `null` = no genesis event on
  // record, reported as unknown rather than filled in.
  genesis_actor: string | null
  created_at: string
}

export interface UnownedSkillPage {
  // Every unowned skill, not just this page - an admin needs the size of the
  // job before starting it.
  total: number
  skills: UnownedSkill[]
}

export interface OwnerAssignmentResult {
  owner: string
  assigned: string[]
  failed: { skill_id: string; error: string }[]
  // ADVISORY, never a failure. `false` means this identity is neither a local
  // account nor has ever appeared as a submitter - the shape a typo takes,
  // and also the shape a brand-new SSO user takes, which is why it warns
  // instead of blocking. `null` means the check could not run. Nothing in
  // `assigned`/`failed` depends on it. See inventory/router.py's
  // `_owner_is_recognized`.
  owner_recognized: boolean | null
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
  // Why `version` is null, set by the backend beside the null itself
  // (`admin.engine_registry.VERSION_UNAVAILABLE_SANDBOXED`). A sandbox engine
  // runs in the separate engine-runner image and the monolith cannot read its
  // metadata at all (INV-15), which is a fact about topology - not a value
  // that failed to load. Null here means the version really is simply absent.
  version_unavailable_reason: string | null
  required: boolean
  enabled: boolean
  capabilities: string[]
}

// GET /v1/admin/engines/health - milestone C Task 10.
export interface EngineHealthCounts {
  ok: number
  partial: number
  error: number
  not_reported: number
  unreadable: number
}

export interface EngineHealth {
  name: string
  observed_scans: number
  counts: EngineHealthCounts
  last_scan_id: string
  last_recorded_at: string
  // TWO fields, never merged - this pair IS the milestone's user-visible goal.
  // `last_report_state` is whether the monolith heard from the engine at all
  // ('reported' / 'not_reported' / 'unreadable'); `last_engine_status` is what
  // the engine said about its own run ('ok' / 'partial' / 'error' / 'timeout'),
  // and is null exactly when the state is not 'reported'. So "returned ERROR"
  // is ('reported', 'error') and "never reported at all" is
  // ('not_reported', null). See engineHealth.ts - never render either raw.
  last_report_state: string
  last_engine_status: string | null
  // THREE states, not two: a positive integer is a measurement, `0` is ALSO a
  // measurement (in-process floor engines finish in under half a millisecond),
  // and `null` means NOT MEASURED - a findings blob written by an
  // engine-runner image older than the field. Rendering null as 0, or as a
  // dash indistinguishable from a real 0, destroys that distinction.
  last_analyze_duration_ms: number | null
  max_analyze_duration_ms: number | null
  measured_duration_count: number
  last_finding_count: number | null
  last_error: string | null
  // Only ever set when the last row was 'not_reported', and only for the two
  // of five causes with a source the backend can read. Null means the cause is
  // not knowable, which the console says out loud rather than guessing.
  not_reported_attribution: string | null
  // The qualifier that travels WITH the token: 'current_config' whenever an
  // attribution is present, null otherwise. Both tokens are read from
  // configuration AT REQUEST TIME - nothing recorded the configuration those
  // scans actually ran under. It is on the wire, not only in this console's
  // hint strings, because this console is not the only possible consumer and a
  // bare `currently_disabled` reads as a fact about the scan. See
  // engine_registry.not_reported_attribution_basis.
  not_reported_attribution_basis: string | null
}

export interface EngineHealthWindow {
  requested_scans: number
  observed_scans: number
  started_at: string | null
  ended_at: string | null
}

export interface EngineHealthReport {
  window: EngineHealthWindow
  engines: EngineHealth[]
  unregistered_engines: string[]
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
