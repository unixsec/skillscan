import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  DEDUP_COLLISION_KEY,
  FINDINGS_CAPPED_KEY,
  HARD_GATE_PREFIX,
  MANUAL_REVIEW_PREFIX,
  reasonLabel,
  SANDBOX_WAIT_TIMEOUT_PREFIX,
  SEVERITY_ALL_PREFIX,
  SEVERITY_NON_LLM_PREFIX,
} from './reasons'
import { makeTranslate, TRANSLATIONS } from './translations'

// The real translator, not a stub - a test that invents its own lookup would
// happily pass against a key that does not exist in translations.ts.
const zh = makeTranslate('zh')
const en = makeTranslate('en')

// Every reason code below is a real gate.decide() output shape; the comments
// name the line that emits it, so a future gate.py change has a trail back
// here.
describe('reasonLabel', () => {
  // Shape 1: key=VALUE (gate.py:189)
  it('renders a key=VALUE severity code with the severity translated', () => {
    expect(zh('severity.critical')).toBe('严重')
    expect(reasonLabel(zh, 'severity_all=CRITICAL')).toBe('全部发现综合严重级别：严重')
    expect(reasonLabel(en, 'severity_all=CRITICAL')).toBe(
      'Combined severity across all findings: Critical',
    )
    expect(reasonLabel(zh, 'severity_non_llm=HIGH')).toBe('非大模型发现的严重级别：高')
  })

  it('echoes an unrecognized severity name instead of a translation key', () => {
    // A severity gate.py grows later must not surface as "severity.apocalyptic".
    const rendered = reasonLabel(zh, 'severity_all=APOCALYPTIC')
    expect(rendered).toContain('APOCALYPTIC')
    expect(rendered).not.toContain('severity.')
  })

  // Shape 2: bare key (gate.py:196, gate.py:191)
  it('renders a bare reason key', () => {
    expect(reasonLabel(zh, 'findings_capped_forces_review')).toBe(
      '发现数量超过展示上限，强制转人工复核',
    )
    expect(reasonLabel(en, 'findings_capped_forces_review')).toBe(
      'Finding count exceeded the display cap - forced to human review',
    )
    expect(reasonLabel(zh, 'dedup_collision_signal_restored_from_scan_result')).toBe(
      '存在去重冲突，已从原始扫描结果恢复被覆盖的信号',
    )
  })

  // hard_gate_hit:<comma-joined rule ids> (gate.py:85)
  it('renders hard-gate hits with the rule ids attached', () => {
    expect(reasonLabel(zh, 'hard_gate_hit:INS-01,SUPPLY-02')).toBe(
      '命中不可豁免的硬门禁规则：INS-01,SUPPLY-02',
    )
  })

  // Shape 3: fail_closed:<cause>:<free-form detail>
  // (gate.py:55-58 + orchestration/service.py:533)
  it('translates the fail-closed cause and attaches the raw runtime detail', () => {
    const code =
      'fail_closed:required_engine_missing_or_failed:engine not registered on this worker'
    expect(reasonLabel(zh, code)).toBe(
      '必需引擎缺失或执行失败，按兜底策略判定：engine not registered on this worker',
    )
    expect(reasonLabel(en, code)).toBe(
      'A required engine was missing or failed - fail-closed verdict: engine not registered on this worker',
    )
  })

  it('keeps a detail that itself contains a colon intact', () => {
    // The detail is free-form runtime text; splitting on every ':' would
    // silently truncate it.
    const rendered = reasonLabel(
      en,
      'fail_closed:required_engine_missing_or_failed:semgrep: exit status 137',
    )
    expect(rendered).toContain('semgrep: exit status 137')
  })

  it('renders a fail-closed code that carries no detail at all', () => {
    // gate.py joins an EMPTY missing_or_failed_required tuple to "" - the
    // trailing colon is still there and must not produce a dangling separator.
    expect(reasonLabel(zh, 'fail_closed:required_engine_missing_or_failed:')).toBe(
      '必需引擎缺失或执行失败，按兜底策略判定',
    )
  })

  it('still frames an unrecognized fail-closed cause as fail-closed, echoing the cause', () => {
    const rendered = reasonLabel(en, 'fail_closed:some_future_cause:raw detail')
    expect(rendered).toContain('some_future_cause')
    expect(rendered).toContain('raw detail')
    expect(rendered.toLowerCase()).toContain('fail-closed')
  })

  // Shape 4: sandbox_wait_timeout:<comma-joined engine names>
  // (orchestration/service.py's sandbox-wait sweep, appended via
  // decide_and_record's extra_reasons). This is the bug the whole-branch
  // review found: it used to fall all the way through to reason.unknown, so
  // the ONE reason a forced-through verdict carried rendered as a raw
  // machine code the user could not act on.
  it('renders a sandbox-wait timeout with the engine list attached', () => {
    expect(reasonLabel(zh, 'sandbox_wait_timeout:semgrep,trufflehog')).toBe(
      '等待沙箱引擎超时，已强制出具判定：semgrep,trufflehog',
    )
    expect(reasonLabel(en, 'sandbox_wait_timeout:semgrep,trufflehog')).toBe(
      'Timed out waiting for sandbox engines - verdict was forced through: semgrep,trufflehog',
    )
  })

  // Shape 5: manual review by <reviewer>: <decision> - <reason>
  // (gate/reviews.py's submit_review_decision). reviewer/decision/reason are
  // all runtime free text - a login name and human-typed strings - so unlike
  // fail_closed's <cause>:<detail>, nothing after the fixed label is parsed;
  // it is echoed whole, including any ':' or ' - ' it happens to contain.
  it('renders a manual review annotation with the whole detail echoed verbatim', () => {
    const code = 'manual review by dev-alice: approve - looks fine, no findings'
    expect(reasonLabel(zh, code)).toBe(
      '人工复核记录：dev-alice: approve - looks fine, no findings',
    )
    expect(reasonLabel(en, code)).toBe(
      'Manual review recorded: dev-alice: approve - looks fine, no findings',
    )
  })

  it('does not mangle a manual review reason that itself contains " - " or ":"', () => {
    const code = 'manual review by bob: reject - failed: secrets in payload - do not merge'
    const rendered = reasonLabel(en, code)
    expect(rendered).toContain(
      'bob: reject - failed: secrets in payload - do not merge',
    )
  })

  // The rule that matters most: never render blank.
  it('echoes an unknown reason code verbatim', () => {
    const rendered = reasonLabel(zh, 'some_reason_gate_py_grew_later')
    expect(rendered).toContain('some_reason_gate_py_grew_later')
    expect(reasonLabel(en, 'some_reason_gate_py_grew_later')).toContain(
      'some_reason_gate_py_grew_later',
    )
  })

  it.each([
    'severity_all=CRITICAL',
    'severity_non_llm=NONE',
    'hard_gate_hit:INS-01',
    'fail_closed:required_engine_missing_or_failed:x',
    'fail_closed:',
    'findings_capped_forces_review',
    'dedup_collision_signal_restored_from_scan_result',
    'sandbox_wait_timeout:semgrep',
    'manual review by alice: approve - fine',
    'totally_unknown',
    '',
  ])('never renders blank, in either locale (%s)', (code) => {
    for (const t of [zh, en]) {
      const rendered = reasonLabel(t, code)
      expect(rendered.trim()).not.toBe('')
      // A leaked translation key would mean a missing entry in translations.ts.
      expect(rendered).not.toMatch(/(^|\s)reason\.[A-Za-z]/)
    }
  })
})

describe('translation dictionaries', () => {
  // The two locales are one contract: a key added to only one of them renders
  // as a raw dotted key for every user of the other.
  it('define exactly the same key set in zh and en', () => {
    const zhKeys = Object.keys(TRANSLATIONS.zh).sort()
    const enKeys = Object.keys(TRANSLATIONS.en).sort()
    expect(zhKeys).toEqual(enKeys)
  })

  it('has no empty translation values', () => {
    for (const [locale, dict] of Object.entries(TRANSLATIONS)) {
      for (const [key, value] of Object.entries(dict)) {
        expect(value, `${locale}.${key} is empty`).not.toBe('')
      }
    }
  })
})

// SECURITY/UX (2026-07-29): the bug this closes was `reasons.test.ts` hand-
// enumerating gate.py's shapes - exactly what a SECOND producer of
// VerdictRow.reasons (orchestration/service.py's sandbox_wait_timeout) is
// invisible to. A full re-derivation of every reason CODE is not honest to
// attempt: two of the three producers build their string by interpolating
// runtime free text (an engine list; a reviewer name and a human-typed
// reason) that has no fixed vocabulary to enumerate. What IS discoverable
// without parsing Python is which FILES write into a reasons-shaped
// variable at all, and whether the literal prefixes/keys this module already
// translates are still textually present in the producer that is supposed to
// emit them. That is weaker than a full contract pin (it cannot invent a
// translation for a brand-new prefix on its own), but it turns both "a new
// file starts writing reasons" and "a known producer renamed its literal"
// into a failing test instead of a silently-blind one.
describe('VerdictRow.reasons producer discovery (parses the real backend tree)', () => {
  const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../..')
  const SCAN_ROOTS = [
    path.join(REPO_ROOT, 'apps/monolith/modules'),
    path.join(REPO_ROOT, 'libs/skillscan_core'),
  ]

  function listPyFiles(dir: string): string[] {
    const out: string[] = []
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'tests' || entry.name === '__pycache__') continue
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        out.push(...listPyFiles(full))
      } else if (entry.name.endsWith('.py') && !entry.name.startsWith('test_')) {
        out.push(full)
      }
    }
    return out
  }

  // Matches every real write site this review found: `VerdictResult(reasons=
  // ...)` / `VerdictRow(..., reasons=reasons, ...)`, `verdict_row.reasons =
  // new_reasons`, and the `new_reasons =` / `extra_reasons =` locals each
  // producer builds on the way there ("reasons =" is a substring of both).
  // Deliberately does NOT match a READ site - `"reasons": v.reasons` (reviews_
  // router.py, gateway/router.py) has no '=' - or a field DECLARATION -
  // `reasons: Mapped[list[str]]` / `reasons: tuple[str, ...]` puts a ':' where
  // this pattern requires '='. Checked by hand against the real tree before
  // being encoded here.
  const REASONS_WRITE_PATTERN = /reasons\s*=/

  // gate/service.py is in the set even though it adds no new literal text of
  // its own - decide_and_record is where gate.py's `reasons` and
  // orchestration's `extra_reasons` are actually merged before the write to
  // VerdictRow, so it legitimately matches the structural pattern too.
  const KNOWN_PRODUCER_FILES = [
    'apps/monolith/modules/gate/reviews.py',
    'apps/monolith/modules/gate/service.py',
    'apps/monolith/modules/orchestration/service.py',
    'libs/skillscan_core/gate.py',
  ].sort()

  it('finds exactly the known files that assign into a *reasons variable', () => {
    const found = SCAN_ROOTS.flatMap((root) => listPyFiles(root))
      .filter((file) => REASONS_WRITE_PATTERN.test(readFileSync(file, 'utf-8')))
      .map((file) => path.relative(REPO_ROOT, file))
      .sort()

    expect(
      found,
      'The set of files writing into a *reasons variable changed. If this is a ' +
        'NEW producer of VerdictRow.reasons, teach i18n/reasons.ts its shape ' +
        '(see the module comment at the top of reasons.ts) and add the file to ' +
        "KNOWN_PRODUCER_FILES here; if a producer was removed, drop it from both.",
    ).toEqual(KNOWN_PRODUCER_FILES)
  })

  const LITERAL_PRESENCE_CASES: Array<[string, string[]]> = [
    [
      'libs/skillscan_core/gate.py',
      [SEVERITY_ALL_PREFIX, SEVERITY_NON_LLM_PREFIX, HARD_GATE_PREFIX, DEDUP_COLLISION_KEY, FINDINGS_CAPPED_KEY],
    ],
    ['apps/monolith/modules/orchestration/service.py', [SANDBOX_WAIT_TIMEOUT_PREFIX]],
    ['apps/monolith/modules/gate/reviews.py', [MANUAL_REVIEW_PREFIX]],
  ]

  // gate/service.py is deliberately absent here (see above: it merges, but
  // emits no reason-code text of its own to anchor on).
  it.each(LITERAL_PRESENCE_CASES)(
    '%s still contains the literal(s) reasons.ts has a translation for',
    (relPath, literals) => {
      const source = readFileSync(path.join(REPO_ROOT, relPath), 'utf-8')
      for (const literal of literals) {
        expect(
          source.includes(literal),
          `${relPath} no longer contains ${JSON.stringify(literal)} - reasons.ts ` +
            'has a translation keyed to a literal this producer stopped emitting ' +
            '(renamed?). Update the matching prefix/key constant in reasons.ts.',
        ).toBe(true)
      }
    },
  )
})
