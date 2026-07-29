import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// Two independent authors have now written a lifecycle state straight into
// JSX instead of through LifecycleBadge/lifecycleLabel (Inventory.tsx's
// InventoryDetailContent, fixed in c7e9bcd; admin/Ownership.tsx, fixed
// alongside this test). Both times the symptom was identical: the raw wire
// value ("published", "blocked", ...) shown in English regardless of locale,
// next to a table one click away that showed the translated, coloured label
// for the exact same state. A third author will make the same mistake unless
// something other than code review catches it - review already missed it
// twice.
//
// This is the same shape as the RETIRE_ELIGIBLE_STATES check in
// Inventory.test.tsx: read the REAL repo source at test time instead of
// hand-asserting a fixed list, so the guard keeps working as pages are added
// or renamed. That test protects the backend-to-frontend direction (a state
// machine edit the console doesn't mirror); this one protects the
// data-to-pixels direction (a lifecycle value the console mirrors correctly
// but forgets to translate).

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url))

// Any object shape that carries a lifecycle `state` field - see api/types.ts.
// A file that never mentions one of these has no lifecycle state to get
// wrong, so it is out of scope for this guard (this is what keeps it from
// firing on unrelated `.state` usage elsewhere, e.g. ScanSummary's scan
// status, or React's own useState).
const LIFECYCLE_CARRYING_TYPES = ['InventorySkill', 'InventoryDetail', 'UnownedSkill']

// The one legitimate way to put a lifecycle state on screen.
const SAFE_APIS = ['LifecycleBadge', 'lifecycleLabel']

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

// Finds JSX expression containers whose entire content is a bare
// `foo.state` (optionally with a `?? fallback`) member access - i.e. the
// value is rendered as-is, with nothing translating it first. Deliberately
// does NOT flag:
//   - `state={s.state}` (prop-passing into LifecycleBadge: preceded by `=`)
//   - `` `${s.state}` `` (a template-literal interpolation, not a JSX
//     expression container: preceded by `$`. This is how the unrelated scan
//     *status* field - a different domain, its own translate-or-echo idiom
//     in Scans.tsx/ScanDetail.tsx - gets built into search-palette text;
//     nothing here claims that pattern is safe, only that it is out of
//     scope for a guard about lifecycle state specifically.)
//   - `{data.state === 'published' && ...}` (a comparison, not a render:
//     nothing follows `.state` matches the "fallback-or-close" tail)
//   - `{lifecycleLabel(t, s.state)}` (already translated: the char class
//     can't skip over the surrounding call's `(t, `)
export function findRawLifecycleStateRenders(source: string): string[] {
  const pattern = /\{\s*([\w.$?]*\.state)(\s*\?\?[^{}]*)?\s*\}/g
  const hits: string[] = []
  for (const m of source.matchAll(pattern)) {
    const precedingChar = source[(m.index ?? 0) - 1]
    if (precedingChar === '=' || precedingChar === '$') continue
    hits.push(m[0])
  }
  return hits
}

describe('findRawLifecycleStateRenders (detector self-test)', () => {
  it('flags a bare state render, with or without a nullish fallback', () => {
    expect(findRawLifecycleStateRenders('<td>{s.state}</td>')).toEqual(['{s.state}'])
    expect(findRawLifecycleStateRenders("<td>{s.state ?? '—'}</td>")).toEqual(["{s.state ?? '—'}"])
    expect(findRawLifecycleStateRenders('<td>\n  {row.state}\n</td>')).toHaveLength(1)
  })

  it('does not flag passing the state into LifecycleBadge as a prop', () => {
    expect(findRawLifecycleStateRenders('<LifecycleBadge state={s.state} />')).toEqual([])
  })

  it('does not flag a comparison or a set-membership check', () => {
    expect(findRawLifecycleStateRenders("{data.state === 'published' && <button />}")).toEqual([])
    expect(
      findRawLifecycleStateRenders('{data.state !== null && ELIGIBLE.has(data.state) && <button />}'),
    ).toEqual([])
  })

  it('does not flag a value already run through the translator', () => {
    expect(findRawLifecycleStateRenders('<span>{lifecycleLabel(t, s.state)}</span>')).toEqual([])
  })

  it('does not flag a template-literal interpolation (out of scope: a different `state` domain)', () => {
    expect(findRawLifecycleStateRenders('`${s.submitter} · ${s.state}`')).toEqual([])
  })
})

describe('no lifecycle state is rendered outside LifecycleBadge/lifecycleLabel', () => {
  const files = listTsxFiles(SRC_DIR).filter((f) => {
    const content = readFileSync(f, 'utf-8')
    return LIFECYCLE_CARRYING_TYPES.some((t) => content.includes(t))
  })

  // Sanity floor: if this ever finds zero files, the scope filter above broke
  // (e.g. the types got renamed) and every assertion below would trivially
  // pass on nothing. Inventory.tsx and admin/Ownership.tsx alone account for
  // at least two today.
  it('found at least the known lifecycle-state-carrying pages', () => {
    expect(files.length).toBeGreaterThanOrEqual(2)
  })

  it.each(files.map((f) => [path.relative(SRC_DIR, f), f] as const))(
    '%s renders any lifecycle state through LifecycleBadge/lifecycleLabel',
    (_label, file) => {
      const content = readFileSync(file, 'utf-8')
      const hits = findRawLifecycleStateRenders(content)
      expect(
        hits,
        `${path.relative(SRC_DIR, file)} renders a lifecycle state raw: ${JSON.stringify(hits)}. ` +
          `Use ${SAFE_APIS.join(' or ')} instead (see Inventory.tsx) so the value is translated ` +
          'and coloured instead of showing the bare wire value in whatever language it happens to be in.',
      ).toEqual([])
    },
  )
})
