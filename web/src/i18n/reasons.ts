// Translates the machine-oriented strings that land in `VerdictRow.reasons`
// into a human sentence - the "依据" every page that shows a verdict owes its
// reader.
//
// Shared deliberately: this used to live inside Reviews.tsx, while ScanDetail
// printed the same codes raw. One implementation, so a reason string reads the
// same wherever the user meets it and a new code only has to be taught here
// once.
//
// SECURITY/UX (2026-07-29, whole-branch review): `VerdictRow.reasons` has
// THREE producers, not one - this module used to scope itself to "every shape
// gate.decide() can emit" and stopped there, so the other two rendered as a
// raw `reason.unknown` code:
//   1. libs/skillscan_core/gate.py's `decide()` - severity_all=/
//      severity_non_llm=/hard_gate_hit:/fail_closed:/the two bare keys below.
//   2. apps/monolith/modules/orchestration/service.py's sandbox-wait sweep -
//      `sandbox_wait_timeout:<engines>`, appended via `decide_and_record`'s
//      `extra_reasons` (gate/service.py) when a verdict is forced through
//      without every sandbox engine reporting.
//   3. apps/monolith/modules/gate/reviews.py's `submit_review_decision` -
//      `manual review by <reviewer>: <decision> - <reason>`, appended when an
//      approver/admin decides a REVIEW-verdict scan by hand. `reviewer` and
//      `reason` are free text a human typed; only the leading label is a
//      translatable frame; see `MANUAL_REVIEW_PREFIX` below.
// `reasons.test.ts` discovers all three by parsing the real source rather
// than hand-enumerating them, for the same reason `Inventory.test.tsx` and
// `lifecycleStateGuard.test.ts` do: a hand-written list is exactly as blind
// as the code it is meant to catch drifting.
//
// Every shape any of the three producers can actually emit is matched
// explicitly; anything else falls through to `reason.unknown`, which still
// shows the RAW code. An unrecognized code means this list has drifted out of
// sync with a producer - that is worth showing, and rendering an empty row
// instead would leave the user with nothing to report.

export type Translate = (key: string, params?: Record<string, string | number>) => string

// Exported (not just module-private) so reasons.test.ts's source-scanning
// guard can check these EXACT literals still appear in the producer that
// emits them, instead of a second hand-copied list living in the test file
// that could itself drift - the same trap this whole module exists to close.
export const SEVERITY_ALL_PREFIX = 'severity_all='
export const SEVERITY_NON_LLM_PREFIX = 'severity_non_llm='
export const HARD_GATE_PREFIX = 'hard_gate_hit:'
export const FAIL_CLOSED_PREFIX = 'fail_closed:'
// orchestration/service.py's sandbox-wait sweep (producer 2 above):
// `sandbox_wait_timeout:<comma-joined engine names>`, structurally identical
// to hard_gate_hit's "prefix + free-form list" shape.
export const SANDBOX_WAIT_TIMEOUT_PREFIX = 'sandbox_wait_timeout:'
// gate/reviews.py's manual-decision annotation (producer 3 above):
// `manual review by <reviewer>: <decision> - <reason>`. Unlike
// fail_closed's `<cause>:<detail>`, NONE of reviewer/decision/reason is a
// fixed vocabulary worth parsing back out - reviewer is a login name and
// reason is free text a human typed, and splitting on ':' or ' - ' would
// silently mis-parse a reviewer name or reason that happens to contain
// either. Translate only the fixed leading label; echo everything after it
// verbatim, exactly like the FAIL_CLOSED_PREFIX branch already does for the
// text that follows fail_closed's own cause code.
export const MANUAL_REVIEW_PREFIX = 'manual review by '
// gate.py's two bare (no interpolation) reason keys - exported for the same
// reason as the prefixes above.
export const DEDUP_COLLISION_KEY = 'dedup_collision_signal_restored_from_scan_result'
export const FINDINGS_CAPPED_KEY = 'findings_capped_forces_review'

// gate.py's fail-closed reason is a THREE-part compound:
//   fail_closed:<cause>:<detail>
// Only <cause> is a machine code with a fixed vocabulary; see gate.py:55-58.
const FAIL_CLOSED_CAUSE_KEYS: Record<string, string> = {
  required_engine_missing_or_failed: 'reason.failClosedRequiredEngine',
}

// t() returns the KEY itself when the dictionary has no entry (see
// makeTranslate in translations.ts) - that identity is how a caller detects
// "no translation exists" without reaching into the dictionary, and it is what
// lets an unknown enum value fall back to its raw wire value instead of
// rendering a bare "severity.apocalyptic" or nothing at all.
function translatedOr(t: Translate, key: string, raw: string): string {
  const translated = t(key)
  return translated === key ? raw : translated
}

// gate.py emits `Severity.name` (NONE/LOW/MEDIUM/HIGH/CRITICAL, uppercase).
function severityLabel(t: Translate, level: string): string {
  return translatedOr(t, `severity.${level.toLowerCase()}`, level)
}

function failClosedLabel(t: Translate, rest: string): string {
  // <detail> is free-form text produced at RUNTIME - a comma-joined list of
  // engine names, or a poison-pill reason string built by
  // orchestration.service.forced_block_scan_result ("engine not registered on
  // this worker"). It is never a translation key and is never looked up as
  // one: it is appended verbatim after the translated part.
  //
  // Split on the FIRST colon only, so a detail that itself contains ':'
  // survives intact.
  const separator = rest.indexOf(':')
  const cause = separator === -1 ? rest : rest.slice(0, separator)
  const detail = separator === -1 ? '' : rest.slice(separator + 1)
  if (cause === '') return t('reason.unknown', { code: FAIL_CLOSED_PREFIX + rest })
  const causeKey = FAIL_CLOSED_CAUSE_KEYS[cause]
  const causeText = causeKey ? t(causeKey) : t('reason.failClosedUnknownCause', { cause })
  return detail === '' ? causeText : t('reason.failClosedDetail', { cause: causeText, detail })
}

export function reasonLabel(t: Translate, code: string): string {
  if (code.startsWith(SEVERITY_ALL_PREFIX)) {
    return t('reason.severityAll', {
      level: severityLabel(t, code.slice(SEVERITY_ALL_PREFIX.length)),
    })
  }
  if (code.startsWith(SEVERITY_NON_LLM_PREFIX)) {
    return t('reason.severityNonLlm', {
      level: severityLabel(t, code.slice(SEVERITY_NON_LLM_PREFIX.length)),
    })
  }
  if (code.startsWith(HARD_GATE_PREFIX)) {
    return t('reason.hardGateHit', { rules: code.slice(HARD_GATE_PREFIX.length) })
  }
  if (code.startsWith(FAIL_CLOSED_PREFIX)) {
    return failClosedLabel(t, code.slice(FAIL_CLOSED_PREFIX.length))
  }
  if (code.startsWith(SANDBOX_WAIT_TIMEOUT_PREFIX)) {
    return t('reason.sandboxWaitTimeout', {
      engines: code.slice(SANDBOX_WAIT_TIMEOUT_PREFIX.length),
    })
  }
  if (code.startsWith(MANUAL_REVIEW_PREFIX)) {
    // {detail} is `<reviewer>: <decision> - <reason>` verbatim - see
    // MANUAL_REVIEW_PREFIX's comment for why it is never parsed further.
    return t('reason.manualReview', { detail: code.slice(MANUAL_REVIEW_PREFIX.length) })
  }
  if (code === DEDUP_COLLISION_KEY) {
    return t('reason.dedupCollision')
  }
  if (code === FINDINGS_CAPPED_KEY) {
    return t('reason.findingsCapped')
  }
  return t('reason.unknown', { code })
}
