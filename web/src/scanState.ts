import type { Translate } from './i18n/reasons'

// Scan-JOB states (apps/monolith/modules/orchestration/service.py's
// SCAN_STATES: queued/running/scored/decided/failed) - unrelated to the skill
// LIFECYCLE states (submitted/scanning/review_pending/published/blocked/
// quarantined/retired) rendered on the Inventory page. The two machines
// happen to each spell a state `running`/`scanning` for "still in flight" -
// DO NOT treat those as the same value or reuse this module for lifecycle
// state: TERMINAL_SCAN_STATES and scanStateLabel below only ever read/write
// the scan-job vocabulary, keyed under the `scanState.` translation prefix
// (lifecycle state has its own `lifecycle.` prefix and its own
// LifecycleBadge/lifecycleLabel in Inventory.tsx).
//
// Deduplicated 2026-07-29 (whole-branch review): TERMINAL_SCAN_STATES used to
// be copy-pasted verbatim into Scans.tsx and ScanDetail.tsx, and the
// translate-or-echo idiom below was hand-written three more times across both
// files - one implementation now, the same move i18n/reasons.ts already made
// for verdict reasons.

// Only `decided`/`failed` are terminal: `scored` always proceeds to `decided`
// within the same worker tick (orchestration.service.aggregate_and_decide,
// right after it sets STATE_SCORED) and is never a resting state -
// marketplace_api.views's own `_STATUS_PROJECTION` independently confirms
// this by mapping `scored` to "RUNNING" and only `decided`/`failed` to
// "COMPLETED". See scanState.test.ts for a guard pinning this against the
// backend's own SCAN_STATES constant.
export const TERMINAL_SCAN_STATES = new Set(['decided', 'failed'])

// Translate a scan-job state, falling back to the raw wire value for a state
// this console has not been taught yet - same "echo, never blank" posture as
// i18n/reasons.ts's reasonLabel, so a state added to SCAN_STATES without a
// matching `scanState.*` translation still shows something instead of a bare
// translation key.
export function scanStateLabel(t: Translate, state: string): string {
  const key = `scanState.${state}`
  const translated = t(key)
  return translated === key ? state : translated
}
