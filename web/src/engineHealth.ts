import type { Translate } from './i18n/reasons'
import type { EngineHealth, EngineInfo } from './api/types'

// Display rules for the admin engine console (milestone C Task 10).
//
// WHY A SEPARATE MODULE, and not inline JSX in Engines.tsx: everything here is
// a decision about whether the console is telling the truth, and all of it is
// provable without a browser, a backend or a database. The three duration
// states in particular came out of two prior tasks that each went out of their
// way to preserve them (Task 7 refused a `.get(field, 0)` default on the wire;
// Task 8 refused a `NOT NULL DEFAULT 0` column), and the last place they can
// still be collapsed is a template that prints them.
//
// It is also what makes `engineHealthStateGuard.test.ts` enforceable: with one
// sanctioned way to turn these values into pixels, "a page rendered the raw
// backend enum" becomes a mechanical check instead of something code review
// has to catch - which it demonstrably does not (c7e9bcd, then again in the
// same session).

// The console's vocabulary for "what happened to this engine last time".
// Derived from the backend's TWO fields plus one state the backend cannot
// send, because it is the absence of a row rather than the content of one.
export type EngineHealthState =
  | 'ok'
  | 'partial'
  | 'error'
  | 'timeout'
  | 'not_reported'
  | 'unreadable'
  // No health row for this engine anywhere in the window. NOT the same as
  // `not_reported`, and keeping them apart is the whole reason this state
  // exists: `not_reported` means we looked for this engine's result on a real
  // scan and found nothing, while `unobserved` means we have no record of the
  // engine being involved in any retained scan at all - which is also what a
  // retention sweep leaves behind. Reporting a swept-away history as "this
  // engine never reports" would be a fabricated engine-level failure.
  | 'unobserved'
  // A report_state/engine_status pair this console has not been taught.
  | 'unknown'

export function engineHealthState(health: EngineHealth | undefined): EngineHealthState {
  if (!health) return 'unobserved'
  if (health.last_report_state === 'not_reported') return 'not_reported'
  if (health.last_report_state === 'unreadable') return 'unreadable'
  if (health.last_report_state !== 'reported') return 'unknown'
  switch (health.last_engine_status) {
    case 'ok':
      return 'ok'
    case 'partial':
      return 'partial'
    case 'error':
      return 'error'
    case 'timeout':
      return 'timeout'
    default:
      return 'unknown'
  }
}

// SECURITY-irrelevant but operationally load-bearing: `error` and
// `not_reported` must not be able to land on the same class. They are the two
// values acceptance criterion 8 exists to separate, so red (badge-block) is
// reserved for "the engine told us it failed" and amber (badge-review) for "we
// never heard from it" - different hue, different text, on top of a different
// English/Chinese label. `unobserved` is deliberately the quietest of the
// three: nothing is known, so nothing should look alarming.
export const ENGINE_HEALTH_BADGE_CLASS: Record<EngineHealthState, string> = {
  ok: 'badge badge-pass',
  partial: 'badge badge-severity-low',
  error: 'badge badge-block',
  timeout: 'badge badge-block',
  not_reported: 'badge badge-review',
  unreadable: 'badge badge-severity-high',
  unobserved: 'badge badge-neutral',
  unknown: 'badge badge-neutral',
}

// Translate-or-echo, the same posture as scanStateLabel/reasonLabel: a state
// the backend grows before this console learns it still shows the raw wire
// value rather than a bare translation key or an empty cell.
export function engineHealthLabel(t: Translate, health: EngineHealth | undefined): string {
  const state = engineHealthState(health)
  if (state === 'unknown' && health) {
    return health.last_engine_status ?? health.last_report_state
  }
  const key = `engineHealth.${state}`
  const translated = t(key)
  return translated === key ? state : translated
}

// The three duration states of `analyze_duration_ms`, plus the structural
// fourth one that sits above the field (no result reached us, so the column
// has nothing to show).
export type EngineDurationDisplay =
  | { kind: 'measured'; ms: number }
  // A measured `0`. `airlock.elapsed_ms` rounds to whole milliseconds, so this
  // means "under half a millisecond", which is what an in-process floor engine
  // genuinely takes. It is a MEASUREMENT and must never render like a blank.
  | { kind: 'sub_millisecond' }
  // `analyze()` ran and its timing is unknown. TWO causes, kept apart by
  // `reason` because they need different hover text: an engine-runner image
  // older than the duration field wrote a valid blob without one, while an
  // `unreadable` row means a blob was written and could not be parsed at all.
  | { kind: 'not_measured'; reason: 'no_duration_field' | 'unreadable_result' }
  // Nothing reached us: no row at all, or a row saying the engine never
  // reported. NOT a claim that `analyze()` never ran - "never dispatched" is
  // only one of that state's five causes, and "crashed after starting" is
  // another. The DB CHECK forces a NULL duration on every non-reported row, so
  // the data cannot distinguish them and this display does not pretend to.
  | { kind: 'no_run' }

export function engineDurationDisplay(health: EngineHealth | undefined): EngineDurationDisplay {
  if (!health) return { kind: 'no_run' }
  // An unreadable blob is EVIDENCE THAT THE ENGINE RAN - something wrote a
  // result and it could not be trusted (aggregate.EngineReportState.UNREADABLE
  // is separate from NOT_REPORTED for exactly that reason). This used to fall
  // into `no_run` beside "never reported", which downgraded a "the engine ran
  // and we lost its output" incident into a blank cell.
  if (health.last_report_state === 'unreadable') {
    return { kind: 'not_measured', reason: 'unreadable_result' }
  }
  if (health.last_report_state !== 'reported') return { kind: 'no_run' }
  // `=== null`, never a falsy test: `0` is a real measurement and `!ms` would
  // silently reclassify every floor engine as unmeasured.
  if (health.last_analyze_duration_ms === null) {
    return { kind: 'not_measured', reason: 'no_duration_field' }
  }
  if (health.last_analyze_duration_ms === 0) return { kind: 'sub_millisecond' }
  return { kind: 'measured', ms: health.last_analyze_duration_ms }
}

export function engineDurationLabel(t: Translate, health: EngineHealth | undefined): string {
  const display = engineDurationDisplay(health)
  switch (display.kind) {
    case 'measured':
      return t('adminEngines.duration.measured', { ms: display.ms })
    case 'sub_millisecond':
      return t('adminEngines.duration.subMillisecond')
    case 'not_measured':
      return t('adminEngines.duration.notMeasured')
    case 'no_run':
      return '—'
  }
}

// The hover text that carries the caveats the cell is too narrow for. Empty
// string when there are none (React omits an empty `title`).
//
// ADDITIVE, not a chain of early returns, which is what it was: the state
// caveat and the window maximum answer different questions, and returning the
// first one found suppressed the second. An engine whose LAST run was a
// sub-millisecond 0 rendered `<1 ms` with no path to the 4756 ms worst case in
// the very same window - the number an operator sizing a scan deadline needs,
// and the only place it is published.
export function engineDurationHint(t: Translate, health: EngineHealth | undefined): string {
  const display = engineDurationDisplay(health)
  const parts: string[] = []
  if (display.kind === 'sub_millisecond') {
    parts.push(t('adminEngines.duration.subMillisecondHint'))
  } else if (display.kind === 'not_measured') {
    parts.push(
      display.reason === 'unreadable_result'
        ? t('adminEngines.duration.unreadableHint')
        : t('adminEngines.duration.notMeasuredHint'),
    )
  }
  // Independent of the state above, including for `no_run`: the window maximum
  // is a fact about the window, not about the last row, and an engine that
  // failed to report THIS time still has a worst case worth seeing. Reported
  // with the count it was taken over, because "slowest in the window" over 1
  // measured run out of 50 says far less than the bare number suggests.
  if (health && health.max_analyze_duration_ms !== null) {
    parts.push(
      t('adminEngines.duration.maxHint', {
        ms: health.max_analyze_duration_ms,
        count: health.measured_duration_count,
      }),
    )
  }
  return parts.join(' ')
}

// What today's configuration would predict about an engine that did not
// report - or the explicit admission that the cause was not observed.
//
// Returns null for every state other than `not_reported`: attaching a cause to
// an engine that reported fine would be noise, and attaching one to an
// `unobserved` engine would be a claim about scans nobody has.
export function notReportedAttributionLabel(
  t: Translate,
  health: EngineHealth | undefined,
): string | null {
  if (engineHealthState(health) !== 'not_reported' || !health) return null
  const attribution = health.not_reported_attribution
  // THE HONEST ANSWER for three of the five causes (never dispatched, still
  // running past the wait, crashed before writing). Saying "cause not
  // recorded" costs an operator nothing; a guess that looks like an
  // observation costs them a wrong fix.
  //
  // `not_reported_attribution_basis` is deliberately NOT read here: it is
  // always 'current_config' when a token is present, and both labels below
  // already open with "current config". It exists on the wire for the
  // consumers that are not this console (see api/types.ts) - a second reader
  // must not have to own a translation table to learn that these are
  // predictions from today's configuration rather than observations.
  if (attribution === null) return t('adminEngines.attribution.unknown')
  const key = `adminEngines.attribution.${attribution}`
  const translated = t(key)
  return translated === key ? attribution : translated
}

export function notReportedAttributionHint(
  t: Translate,
  health: EngineHealth | undefined,
): string {
  if (engineHealthState(health) !== 'not_reported' || !health) return ''
  const attribution = health.not_reported_attribution ?? 'unknown'
  const key = `adminEngines.attributionHint.${attribution}`
  const translated = t(key)
  return translated === key ? '' : translated
}

// The `version` column. Lives here rather than in the page for the same reason
// as everything above: "—" was being shown for two completely different facts
// (a sandbox engine whose metadata this process structurally cannot reach, and
// a genuinely absent value), and one function is where that stops.
export function engineVersionLabel(t: Translate, engine: EngineInfo): string {
  if (engine.version !== null) return engine.version
  if (engine.version_unavailable_reason === null) return '—'
  const key = `adminEngines.versionUnavailable.${engine.version_unavailable_reason}`
  const translated = t(key)
  return translated === key ? engine.version_unavailable_reason : translated
}
