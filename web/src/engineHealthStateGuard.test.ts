import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// Sibling of lifecycleStateGuard.test.ts, for a second family of backend enums.
//
// WHY A SECOND GUARD RATHER THAN WIDENING THE FIRST: that one matches a
// literal `.state` member access, and these fields are `report_state` /
// `engine_status` - the character before "state" is an underscore, not a dot,
// so it cannot see them and never could. The failure mode is identical though,
// and this session has now produced it twice (c7e9bcd, then again in Task 15's
// new table): a page renders the raw wire value in English regardless of
// locale, one click away from a sibling that shows the translated label.
//
// `report_state` and `engine_status` are the pair that milestone C exists to
// keep apart ("returned ERROR" vs "never reported at all"). Rendering either
// raw would put `not_reported` on screen as a bare token - which is not only
// untranslated but actively misleading, since the console's own vocabulary
// distinguishes it from `unobserved`, and the wire value does not.

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url))

// Any object shape carrying engine-health enums - see api/types.ts. A file
// that never mentions one has nothing to get wrong, which is what keeps this
// from firing on unrelated code.
//
// 2026-07-30: `ScanEngineCoverage` / `ScanEngineCoverageEntry` are the SECOND
// backend surface carrying `report_state` + `engine_status` (per-scan coverage,
// with unprefixed field names), and `EngineObservation` is the shape
// engineHealth.ts now renders. Added here BY HAND, because this list is exactly
// the kind of sibling registry this codebase has repeatedly failed to update
// alongside a new producer - and a guard whose scope filter misses the new file
// passes forever.
const HEALTH_CARRYING_TYPES = [
  'EngineHealth',
  'EngineHealthReport',
  'EngineObservation',
  'ScanEngineCoverage',
]

// The one legitimate way to put these values on screen.
const SAFE_APIS = ['EngineHealthBadge', 'engineHealthLabel']

const RAW_FIELDS = ['report_state', 'engine_status']

function listTsxFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...listTsxFiles(full))
    } else if (entry.name.endsWith('.tsx') && !entry.name.endsWith('.test.tsx')) {
      out.push(full)
    }
  }
  return out
}

// Finds JSX expression containers whose entire content is a bare member access
// ending in one of the health enum fields, with or without a nullish fallback.
// Same construction as findRawLifecycleStateRenders, and it deliberately does
// NOT flag:
//   - `health={h.last_report_state}` (prop-passing: preceded by `=`)
//   - `` `${h.last_report_state}` `` (template interpolation: preceded by `$`)
//   - `{h.last_report_state === 'reported' && ...}` (a comparison, not a render)
//   - `{engineHealthLabel(t, h)}` (already translated)
//
// Matched as a SUFFIX (`[\w$]*` before the field name) because the wire fields
// are `last_report_state` / `last_engine_status`: an exact `\.report_state`
// would have matched nothing that this codebase actually writes, and a guard
// that matches nothing passes forever.
export function findRawEngineHealthRenders(source: string): string[] {
  const fields = RAW_FIELDS.join('|')
  const pattern = new RegExp(
    `\\{\\s*([\\w.$?]*\\.[\\w$]*(?:${fields}))(\\s*\\?\\?[^{}]*)?\\s*\\}`,
    'g',
  )
  const hits: string[] = []
  for (const m of source.matchAll(pattern)) {
    const precedingChar = source[(m.index ?? 0) - 1]
    if (precedingChar === '=' || precedingChar === '$') continue
    hits.push(m[0])
  }
  return hits
}

describe('findRawEngineHealthRenders (detector self-test)', () => {
  it('flags a bare render of either field, with or without a fallback', () => {
    expect(findRawEngineHealthRenders('<td>{h.last_report_state}</td>')).toEqual([
      '{h.last_report_state}',
    ])
    expect(findRawEngineHealthRenders("<td>{h.last_engine_status ?? '—'}</td>")).toEqual([
      "{h.last_engine_status ?? '—'}",
    ])
  })

  it('does not flag prop-passing into the badge', () => {
    expect(findRawEngineHealthRenders('<Badge state={h.last_report_state} />')).toEqual([])
  })

  it('does not flag a comparison', () => {
    expect(findRawEngineHealthRenders("{h.last_report_state === 'reported' && <span />}")).toEqual(
      [],
    )
  })

  it('does not flag a value already run through the translator', () => {
    expect(findRawEngineHealthRenders('<span>{engineHealthLabel(t, h)}</span>')).toEqual([])
  })

  it('does not flag a template-literal interpolation', () => {
    expect(findRawEngineHealthRenders('`${h.name} · ${h.last_report_state}`')).toEqual([])
  })
})

describe('no engine-health enum is rendered outside EngineHealthBadge/engineHealthLabel', () => {
  const files = listTsxFiles(SRC_DIR).filter((f) => {
    const content = readFileSync(f, 'utf-8')
    return HEALTH_CARRYING_TYPES.some((t) => content.includes(t))
  })

  // Sanity floor, same as the lifecycle guard's: if the scope filter ever
  // matches nothing (the types got renamed), every assertion below would pass
  // trivially on an empty list. admin/Engines.tsx, components/Badge.tsx and
  // pages/ScanDetail.tsx account for three today.
  it('found at least the known engine-health-carrying files', () => {
    expect(files.length).toBeGreaterThanOrEqual(3)
  })

  it.each(files.map((f) => [path.relative(SRC_DIR, f), f] as const))(
    '%s renders engine health through the sanctioned API',
    (_label, file) => {
      const content = readFileSync(file, 'utf-8')
      const hits = findRawEngineHealthRenders(content)
      expect(
        hits,
        `${path.relative(SRC_DIR, file)} renders an engine-health enum raw: ${JSON.stringify(hits)}. ` +
          `Use ${SAFE_APIS.join(' or ')} instead (see pages/admin/Engines.tsx) - a raw ` +
          '`not_reported` on screen is both untranslated and indistinguishable from ' +
          '"no record in this window", which is a different fact.',
      ).toEqual([])
    },
  )
})
