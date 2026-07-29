import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { scanStateLabel, TERMINAL_SCAN_STATES } from './scanState'
import { makeTranslate, TRANSLATIONS } from './i18n/translations'

const zh = makeTranslate('zh')
const en = makeTranslate('en')

describe('scanStateLabel', () => {
  it('translates a known scan state in both locales', () => {
    expect(scanStateLabel(zh, 'decided')).toBe('已裁决')
    expect(scanStateLabel(en, 'decided')).toBe('Decided')
  })

  it('echoes an unrecognized scan state instead of a translation key', () => {
    expect(scanStateLabel(zh, 'some_future_state')).toBe('some_future_state')
    expect(scanStateLabel(zh, 'some_future_state')).not.toMatch(/scanState\./)
  })
})

// SECURITY/UX: the lifecycle state machine got a cross-source pin test
// (Inventory.test.tsx's RETIRE_ELIGIBLE_STATES check) after two authors wrote
// a raw lifecycle value straight into JSX; the scan-job machine never got the
// equivalent. This is the weaker-but-honest version of that pin: it does not
// re-derive TERMINAL_SCAN_STATES structurally (unlike VALID_TRANSITIONS,
// orchestration/service.py has no per-state "leads to terminal" table to
// read - `scored` reaching `decided`/`failed` is a same-tick runtime
// guarantee documented in prose and separately enforced by
// test_marketplace_views.py, not a static edge list), but it does parse the
// real `SCAN_STATES` constant and fail if either (a) TERMINAL_SCAN_STATES
// stops being a subset of it (a renamed/removed state silently breaks
// polling termination) or (b) a state SCAN_STATES gained has no
// `scanState.*` translation on either side (it would still echo rather than
// break, but silently showing an untranslated wire value is the same defect
// class this branch's review is closing elsewhere).
describe('TERMINAL_SCAN_STATES is pinned to orchestration/service.py SCAN_STATES', () => {
  const servicePath = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../apps/monolith/modules/orchestration/service.py',
  )
  const source = readFileSync(servicePath, 'utf-8')

  function backendScanStates(): Set<string> {
    const constants = new Map<string, string>()
    for (const [, name, value] of source.matchAll(/^STATE_(\w+) = "(\w+)"$/gm)) {
      constants.set(`STATE_${name}`, value)
    }
    const setMatch = source.match(/SCAN_STATES: frozenset\[str] = frozenset\(\s*\{([^}]*)}/)
    if (!setMatch) {
      throw new Error(
        'could not find SCAN_STATES in orchestration/service.py - its declaration shape ' +
          'changed; update this regex (and re-check TERMINAL_SCAN_STATES by hand) rather ' +
          'than deleting the test',
      )
    }
    const members = setMatch[1]
      .split(',')
      .map((m) => m.trim())
      .filter((m) => m.length > 0)
    const states = new Set<string>()
    for (const member of members) {
      const value = constants.get(member)
      if (value === undefined) {
        throw new Error(`SCAN_STATES references ${member}, but no "STATE_X = ..." defined it`)
      }
      states.add(value)
    }
    return states
  }

  it('found the real state machine (sanity floor)', () => {
    // Known count today: queued, running, scored, decided, failed.
    expect(backendScanStates().size).toBeGreaterThanOrEqual(5)
  })

  it('every TERMINAL_SCAN_STATES member is a real backend scan state', () => {
    const backend = backendScanStates()
    for (const state of TERMINAL_SCAN_STATES) {
      expect(backend.has(state), `"${state}" is not in orchestration.service.SCAN_STATES`).toBe(
        true,
      )
    }
  })

  it('every backend scan state has a scanState.* translation in both locales', () => {
    const missing: string[] = []
    for (const state of backendScanStates()) {
      const key = `scanState.${state}`
      if (!(key in TRANSLATIONS.zh) || !(key in TRANSLATIONS.en)) missing.push(state)
    }
    expect(
      missing,
      `states with no scanState.* translation (would render the raw wire value): ${missing}`,
    ).toEqual([])
  })
})
