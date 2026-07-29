import { describe, expect, it } from 'vitest'
import { makeTranslate, TRANSLATIONS } from './i18n/translations'
import {
  ENGINE_HEALTH_BADGE_CLASS,
  engineDurationDisplay,
  engineDurationHint,
  engineDurationLabel,
  engineHealthLabel,
  engineHealthState,
  engineVersionLabel,
  notReportedAttributionHint,
  notReportedAttributionLabel,
  type EngineHealthState,
} from './engineHealth'
import type { EngineHealth, EngineInfo } from './api/types'

// Uses the REAL translator over the REAL dictionary (same as scanState.test.ts
// and i18n/reasons.test.ts): a test with a stub `t` passes happily against
// keys that do not exist in translations.ts.
const zh = makeTranslate('zh')
const en = makeTranslate('en')

function health(overrides: Partial<EngineHealth> = {}): EngineHealth {
  return {
    name: 'bandit',
    observed_scans: 3,
    counts: { ok: 3, partial: 0, error: 0, not_reported: 0, unreadable: 0 },
    last_scan_id: 'scan-1',
    last_recorded_at: '2026-07-29T12:00:00',
    last_report_state: 'reported',
    last_engine_status: 'ok',
    last_analyze_duration_ms: 42,
    max_analyze_duration_ms: 90,
    measured_duration_count: 3,
    last_finding_count: 0,
    last_error: null,
    not_reported_attribution: null,
    not_reported_attribution_basis: null,
    ...overrides,
  }
}

const NEVER_REPORTED = health({
  last_report_state: 'not_reported',
  last_engine_status: null,
  last_analyze_duration_ms: null,
  max_analyze_duration_ms: null,
  measured_duration_count: 0,
  last_finding_count: null,
  last_error: 'no findings reported at findings/scan-1/aig-mcp-scan.json',
  counts: { ok: 0, partial: 0, error: 0, not_reported: 3, unreadable: 0 },
})

const RETURNED_ERROR = health({
  last_engine_status: 'error',
  last_error: 'adapter exited 1',
  counts: { ok: 0, partial: 0, error: 3, not_reported: 0, unreadable: 0 },
})

describe('"returned ERROR" and "never reported" are visibly different', () => {
  // Milestone C acceptance criterion 8, at the last layer where it can still
  // be lost. Three independent channels must differ, not one: an operator
  // reading the table at a glance sees colour, an operator reading the cell
  // sees words, and a colour-blind operator still has the words.
  it('derives two different states', () => {
    expect(engineHealthState(RETURNED_ERROR)).toBe('error')
    expect(engineHealthState(NEVER_REPORTED)).toBe('not_reported')
  })

  it('renders two different labels in both locales', () => {
    expect(engineHealthLabel(zh, RETURNED_ERROR)).not.toBe(engineHealthLabel(zh, NEVER_REPORTED))
    expect(engineHealthLabel(en, RETURNED_ERROR)).not.toBe(engineHealthLabel(en, NEVER_REPORTED))
    expect(engineHealthLabel(zh, RETURNED_ERROR)).toBe('返回错误')
    expect(engineHealthLabel(zh, NEVER_REPORTED)).toBe('从未上报')
    expect(engineHealthLabel(en, RETURNED_ERROR)).toBe('returned an error')
    expect(engineHealthLabel(en, NEVER_REPORTED)).toBe('never reported')
  })

  it('renders two different badge classes', () => {
    expect(ENGINE_HEALTH_BADGE_CLASS.error).not.toBe(ENGINE_HEALTH_BADGE_CLASS.not_reported)
  })

  it('gives "never reported" an attribution line and "returned an error" none', () => {
    expect(notReportedAttributionLabel(zh, RETURNED_ERROR)).toBeNull()
    expect(notReportedAttributionLabel(zh, NEVER_REPORTED)).not.toBeNull()
  })
})

describe('the third state: no observation at all', () => {
  // The retention sweep (Task 9) removes old rows. When it does, engines drop
  // out of the window entirely - and that must not read as "never reported",
  // which is a claim about a scan that really did run.
  it('an engine with no row is neither ok nor never-reported', () => {
    expect(engineHealthState(undefined)).toBe('unobserved')
    expect(engineHealthLabel(zh, undefined)).toBe('窗口内无记录')
    expect(engineHealthLabel(en, undefined)).toBe('no record in window')
  })

  it('is a different label and class from "never reported"', () => {
    expect(engineHealthLabel(zh, undefined)).not.toBe(engineHealthLabel(zh, NEVER_REPORTED))
    expect(ENGINE_HEALTH_BADGE_CLASS.unobserved).not.toBe(ENGINE_HEALTH_BADGE_CLASS.not_reported)
  })

  it('carries no attribution, because there is nothing to attribute', () => {
    expect(notReportedAttributionLabel(zh, undefined)).toBeNull()
    expect(notReportedAttributionHint(zh, undefined)).toBe('')
  })
})

describe('the three duration states', () => {
  // Task 7 refused a `.get(field, 0)` default on the wire and Task 8 refused a
  // `NOT NULL DEFAULT 0` column, both to keep these apart. A template is the
  // last place they can still be collapsed.
  it('0 is a measurement, not a blank', () => {
    const h = health({ last_analyze_duration_ms: 0, max_analyze_duration_ms: 0 })
    expect(engineDurationDisplay(h)).toEqual({ kind: 'sub_millisecond' })
    expect(engineDurationLabel(zh, h)).toBe('<1 毫秒')
    expect(engineDurationLabel(en, h)).toBe('<1 ms')
    expect(engineDurationHint(en, h)).toContain('real measurement')
  })

  it('null is NOT MEASURED, and says so rather than showing a dash', () => {
    const h = health({ last_analyze_duration_ms: null, max_analyze_duration_ms: null })
    expect(engineDurationDisplay(h)).toEqual({ kind: 'not_measured', reason: 'no_duration_field' })
    expect(engineDurationLabel(zh, h)).toBe('未测量')
    expect(engineDurationLabel(en, h)).toBe('not measured')
    expect(engineDurationHint(en, h)).toContain('older than the field')
  })

  it('a positive integer renders as the measurement it is', () => {
    const h = health({ last_analyze_duration_ms: 42 })
    expect(engineDurationDisplay(h)).toEqual({ kind: 'measured', ms: 42 })
    expect(engineDurationLabel(zh, h)).toBe('42 毫秒')
    expect(engineDurationLabel(en, h)).toBe('42 ms')
  })

  it('all three render differently from each other in both locales', () => {
    const rendered = (t: typeof zh) =>
      [
        engineDurationLabel(t, health({ last_analyze_duration_ms: 0 })),
        engineDurationLabel(t, health({ last_analyze_duration_ms: null })),
        engineDurationLabel(t, health({ last_analyze_duration_ms: 42 })),
        engineDurationLabel(t, NEVER_REPORTED),
      ]
    for (const t of [zh, en]) {
      expect(new Set(rendered(t)).size).toBe(4)
    }
  })

  it('an engine that never reported shows no duration at all - no result reached us', () => {
    expect(engineDurationDisplay(NEVER_REPORTED)).toEqual({ kind: 'no_run' })
    expect(engineDurationLabel(zh, NEVER_REPORTED)).toBe('—')
    expect(engineDurationDisplay(undefined)).toEqual({ kind: 'no_run' })
  })

  it('an UNREADABLE result is not-measured, because analyze() demonstrably ran', () => {
    // 2026-07-29. `unreadable` used to land in `no_run` beside "never
    // reported", under a comment claiming "there was no analyze() call to
    // time". An unreadable row means something WROTE a result and it could not
    // be trusted (aggregate.EngineReportState keeps UNREADABLE and
    // NOT_REPORTED apart for exactly that reason) - the engine ran and its
    // timing is unknown, which is the definition of not-measured. The DB CHECK
    // forces a NULL duration on every non-reported row, so the data cannot
    // distinguish it; the display must not claim more than the data holds.
    const unreadable = health({
      last_report_state: 'unreadable',
      last_engine_status: null,
      last_analyze_duration_ms: null,
      max_analyze_duration_ms: null,
      measured_duration_count: 0,
    })
    expect(engineDurationDisplay(unreadable)).toEqual({
      kind: 'not_measured',
      reason: 'unreadable_result',
    })
    expect(engineDurationLabel(en, unreadable)).toBe('not measured')
    expect(engineDurationLabel(en, unreadable)).not.toBe('—')
  })

  it('the two not-measured causes get different hover text', () => {
    // Same cell text, different reason: "the image predates the field" would
    // send an operator to check a version, and "the blob could not be parsed"
    // to check the blob. One hint for both would be wrong for one of them.
    const stale = health({ last_analyze_duration_ms: null, max_analyze_duration_ms: null })
    const unreadable = health({
      last_report_state: 'unreadable',
      last_engine_status: null,
      last_analyze_duration_ms: null,
      max_analyze_duration_ms: null,
    })
    for (const t of [zh, en]) {
      expect(engineDurationHint(t, stale)).not.toBe(engineDurationHint(t, unreadable))
    }
    expect(engineDurationHint(en, unreadable)).toContain('could not be parsed')
    expect(engineDurationHint(en, unreadable)).toContain('DID run')
  })

  it('a falsy-vs-null confusion cannot survive: 0 and null take different branches', () => {
    // Written as its own assertion because `if (!ms)` is the natural way to
    // write this and is wrong for exactly one value.
    expect(engineDurationDisplay(health({ last_analyze_duration_ms: 0 })).kind).not.toBe(
      engineDurationDisplay(health({ last_analyze_duration_ms: null })).kind,
    )
  })

  it('the max-duration hint only appears when there is a measured max', () => {
    expect(engineDurationHint(en, health({ max_analyze_duration_ms: 900 }))).toContain('900')
    expect(
      engineDurationHint(en, health({ last_analyze_duration_ms: 5, max_analyze_duration_ms: null })),
    ).toBe('')
  })

  it('the window maximum survives a last run that was 0 or unmeasured', () => {
    // THE BUG (2026-07-29): the hint used to return the state caveat and stop,
    // so an engine whose last run happened to be a sub-millisecond 0 rendered
    // `<1 ms` with NO path to the 4756 ms worst case in the same window - the
    // number an operator sizing SKILLSCAN_SCAN_DEADLINE_S actually needs, and
    // the only place it is published.
    const floorEngine = health({
      last_analyze_duration_ms: 0,
      max_analyze_duration_ms: 4756,
      measured_duration_count: 50,
    })
    const hint = engineDurationHint(en, floorEngine)
    expect(hint).toContain('4756')
    // ...without losing the caveat that used to crowd it out.
    expect(hint).toContain('real measurement')

    const noDurationField = health({
      last_analyze_duration_ms: null,
      max_analyze_duration_ms: 4756,
      measured_duration_count: 1,
    })
    expect(engineDurationHint(en, noDurationField)).toContain('4756')
    expect(engineDurationHint(en, noDurationField)).toContain('older than the field')

    // Even for a row that did not report: the maximum is a fact about the
    // WINDOW, not about the last run.
    expect(
      engineDurationHint(en, { ...NEVER_REPORTED, max_analyze_duration_ms: 4756 }),
    ).toContain('4756')
  })

  it('the window maximum is reported with how many runs were actually timed', () => {
    // "Slowest in window: 4756 ms" over 1 timed run out of 50 reads as a
    // property of the window and is a property of one sample.
    expect(
      engineDurationHint(en, health({ max_analyze_duration_ms: 4756, measured_duration_count: 1 })),
    ).toContain('the 1 runs in it that were timed')
    expect(
      engineDurationHint(zh, health({ max_analyze_duration_ms: 4756, measured_duration_count: 1 })),
    ).toContain('共 1 次测到耗时')
  })
})

describe('not_reported attribution: two knowable causes, three that are not', () => {
  function neverReportedWith(attribution: string | null): EngineHealth {
    return {
      ...NEVER_REPORTED,
      not_reported_attribution: attribution,
      not_reported_attribution_basis: attribution === null ? null : 'current_config',
    }
  }

  it('names the LLM cause as this service’s own config, not the other pod’s behaviour', () => {
    // 2026-07-29. The token used to be `never_constructed` and rendered "not
    // built in this deployment" - a claim about the engine-runner that this
    // console's backend cannot check, and one that is simply false in the
    // split brain it was written for (engine-runner has the endpoint, the
    // monolith does not, the engine runs and is slow). The label may state
    // only what was read here; construction belongs in a conditional.
    const label = notReportedAttributionLabel(en, neverReportedWith('llm_endpoint_unconfigured'))
    expect(label).toBe('current config: no internal LLM endpoint on this service')
    expect(label).not.toContain('not built')
    const hint = notReportedAttributionHint(en, neverReportedWith('llm_endpoint_unconfigured'))
    expect(hint).toContain('not an observation')
    // The conditional, and the disagreement it exists for.
    expect(hint).toContain('sharing that configuration')
    expect(hint).toContain('If the two disagree')
    const zhHint = notReportedAttributionHint(zh, neverReportedWith('llm_endpoint_unconfigured'))
    expect(zhHint).toContain('若两边配置不一致')
  })

  it('names the toggle cause with the same caveat', () => {
    expect(notReportedAttributionLabel(zh, neverReportedWith('currently_disabled'))).toBe(
      '当前配置：该引擎已被停用',
    )
    expect(notReportedAttributionHint(en, neverReportedWith('currently_disabled'))).toContain(
      'not evidence',
    )
  })

  it('says "cause not recorded" for the three that cannot be known', () => {
    expect(notReportedAttributionLabel(zh, neverReportedWith(null))).toBe('原因未记录')
    expect(notReportedAttributionLabel(en, neverReportedWith(null))).toBe('cause not recorded')
    expect(notReportedAttributionHint(en, neverReportedWith(null))).toContain('none is inferred')
  })

  it('echoes an attribution this console has not been taught rather than blanking it', () => {
    expect(notReportedAttributionLabel(en, neverReportedWith('a_future_cause'))).toBe(
      'a_future_cause',
    )
  })
})

describe('a state the backend grows before the console learns it', () => {
  it('echoes the raw value instead of a bare translation key', () => {
    const future = health({ last_report_state: 'reported', last_engine_status: 'degraded' })
    expect(engineHealthState(future)).toBe('unknown')
    expect(engineHealthLabel(en, future)).toBe('degraded')
    const futureState = health({ last_report_state: 'quarantined', last_engine_status: null })
    expect(engineHealthLabel(en, futureState)).toBe('quarantined')
  })
})

describe('version', () => {
  function engine(overrides: Partial<EngineInfo> = {}): EngineInfo {
    return {
      name: 'bandit',
      version: null,
      version_unavailable_reason: null,
      required: false,
      enabled: true,
      capabilities: [],
      ...overrides,
    }
  }

  it('a sandbox engine says why there is no version instead of showing a bare dash', () => {
    const e = engine({ version_unavailable_reason: 'sandboxed_image' })
    expect(engineVersionLabel(zh, e)).toBe('不可读取（沙箱镜像）')
    expect(engineVersionLabel(en, e)).toBe('not readable (sandboxed image)')
    expect(engineVersionLabel(en, e)).not.toBe('—')
  })

  it('a real version is shown verbatim', () => {
    expect(engineVersionLabel(en, engine({ version: '1.2.3' }))).toBe('1.2.3')
  })

  it('a genuinely missing value with no stated reason is still a dash', () => {
    expect(engineVersionLabel(en, engine())).toBe('—')
  })
})

describe('every health state has a label in BOTH locales', () => {
  // Not "the key sets are equal" (reasons.test.ts already asserts that
  // globally) - this asserts the states this module can actually PRODUCE are
  // all translated, so adding a state to the union without adding its two
  // strings fails here rather than showing `engineHealth.foo` on screen.
  const states: EngineHealthState[] = Object.keys(
    ENGINE_HEALTH_BADGE_CLASS,
  ) as EngineHealthState[]

  it.each(states)('%s', (state) => {
    for (const locale of ['zh', 'en'] as const) {
      expect(TRANSLATIONS[locale][`engineHealth.${state}`]).toBeTruthy()
    }
  })

  it('covers every state the deriving function can return', () => {
    expect(states).toContain('unobserved')
    expect(states).toContain('not_reported')
    expect(states).toContain('error')
  })
})
