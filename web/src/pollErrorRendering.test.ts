import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// `useApiData` returns TWO failure fields and they mean different things
// (5873a1f): `error` is "there is nothing to show you" and blanks the page via
// DataState, while `pollError` is "what is on screen may be stale" and must be
// rendered NEXT TO the data. Only a polling caller can ever see the second one
// - `pollError` is written only on the poll path, and the hook installs no
// timers at all without `pollWhile` - so today exactly two pages destructure it
// and the rest are correct to ignore it.
//
// The gap is the NEXT polling page. Adding `pollWhile` is a one-line change and
// nothing about it says "you now own a second failure field"; the page keeps
// compiling, keeps passing its own tests, and silently drops the staleness
// notice on every failed refresh. That is the shape this repo keeps paying for
// - a second registry nobody updated - and a comment on the hook would be the
// same review-only defence that already missed it twice for lifecycle states
// (see lifecycleStateGuard.test.ts, which is the pattern this follows).
//
// Deliberately NOT solved structurally in the hook or in DataState: rendering
// pollError inside DataState would still need every caller to pass it, and
// making DataState take the whole hook result would rewrite a dozen correct
// call sites to guard against a mistake nobody has made yet. This test costs
// one file and fails on the exact edit that would introduce the bug.

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url))

function listSourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...listSourceFiles(full))
    } else if (
      (entry.name.endsWith('.tsx') || entry.name.endsWith('.ts')) &&
      !entry.name.endsWith('.test.tsx') &&
      !entry.name.endsWith('.test.ts') &&
      !entry.name.endsWith('.d.ts')
    ) {
      out.push(full)
    }
  }
  return out
}

// The hook itself defines both fields, so it would match every pattern here and
// prove nothing. Excluded by path, not by a name check, so a rename cannot
// silently widen the exemption.
const HOOK_FILE = path.join(SRC_DIR, 'api', 'useApiData.ts')

// A `useApiData(...)` call that asks for polling. Matched from the call site to
// the `pollWhile` key rather than by parsing the argument list: the option can
// be written inline or hoisted into a variable, and both spellings are the same
// mistake. `[\s\S]{0,400}` bounds the window so a `pollWhile` belonging to some
// unrelated later call cannot be attributed to this one.
const POLLING_CALL = /useApiData\s*<?[\s\S]{0,400}?pollWhile/

describe('every polling page renders the staleness notice', () => {
  const pollingFiles = listSourceFiles(SRC_DIR)
    .filter((file) => file !== HOOK_FILE)
    .filter((file) => POLLING_CALL.test(readFileSync(file, 'utf-8')))

  it('finds the polling pages at all (a guard that matches nothing guards nothing)', () => {
    // Non-vacuity, asserted rather than assumed. If a refactor moves polling
    // somewhere this walker does not look, the loop below would pass by finding
    // zero files - the failure mode that makes source-scanning tests worthless.
    expect(pollingFiles.length).toBeGreaterThanOrEqual(2)
  })

  it.each(
    listSourceFiles(SRC_DIR)
      .filter((file) => file !== HOOK_FILE)
      .filter((file) => POLLING_CALL.test(readFileSync(file, 'utf-8')))
      .map((file) => path.relative(SRC_DIR, file)),
  )('%s destructures and renders pollError', (relative) => {
    const source = readFileSync(path.join(SRC_DIR, relative), 'utf-8')
    expect(
      source.includes('pollError'),
      `${relative} calls useApiData with pollWhile but never mentions pollError. A failed ` +
        'background refresh there is invisible: the data on screen silently stops advancing ' +
        'while the page still looks live. Render it next to the data (see Scans.tsx), NOT ' +
        'through DataState - that would blank the whole page on one transient 503.',
    ).toBe(true)
    // Mentioning it is not rendering it. Both existing callers reach for the
    // same shared string, which is also what keeps the wording consistent
    // between them and translated in both locales.
    expect(
      source.includes('common.refreshFailed'),
      `${relative} destructures pollError but never renders it through ` +
        "t('common.refreshFailed') - the reader is still not told the view may be stale.",
    ).toBe(true)
  })
})
