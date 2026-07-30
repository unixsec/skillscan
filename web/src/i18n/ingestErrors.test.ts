import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  INGEST_ERROR_PREFIX,
  INGEST_REASON_LITERALS,
  ingestErrorMessage,
} from './ingestErrors'
import { makeTranslate, TRANSLATIONS } from './translations'

// The real translator, not a stub - a test with its own lookup would happily
// pass against a key that does not exist in translations.ts.
const zh = makeTranslate('zh')
const en = makeTranslate('en')

const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../..')
const NORMALIZER = path.join(REPO_ROOT, 'services/engine_runner/normalizer.py')
const PRODUCERS = [
  path.join(REPO_ROOT, 'apps/monolith/modules/gateway/router.py'),
  path.join(REPO_ROOT, 'apps/monolith/modules/marketplace_api/router.py'),
]

describe('ingestErrorMessage', () => {
  it('translates the tar-only rejection a real zip upload used to get', () => {
    const detail = `${INGEST_ERROR_PREFIX}not a valid tar archive: file could not be opened successfully`
    expect(ingestErrorMessage(zh, detail)).toContain('zip')
    expect(ingestErrorMessage(zh, detail)).not.toContain('not a valid tar')
    expect(ingestErrorMessage(en, detail)).toContain('tar')
  })

  it('translates every resource bound distinctly', () => {
    const messages = [
      'archive size 99999999 exceeds max 52428800 bytes',
      'entry count 6000 exceeds max 5000',
      "member 'big.bin' declared size 99999999 exceeds max 20971520",
      'total uncompressed size exceeds max 209715200',
      'compression ratio 1015.0 exceeds max 100 (decompression-bomb defense)',
    ].map((reason) => ingestErrorMessage(zh, INGEST_ERROR_PREFIX + reason))
    // Five bounds, five different sentences: collapsing them would tell a user
    // "too big" when the real problem is the number of files.
    expect(new Set(messages).size).toBe(5)
    for (const message of messages) {
      expect(message).not.toContain('exceeds max')
      expect(message).not.toMatch(/^ingest\./)
    }
  })

  it('translates the zip-specific refusals', () => {
    const encrypted = ingestErrorMessage(
      zh,
      `${INGEST_ERROR_PREFIX}encrypted zip entries are rejected: 'secret.txt'`,
    )
    const spanned = ingestErrorMessage(
      zh,
      `${INGEST_ERROR_PREFIX}spanned/multi-disk zip archives are not supported (disk 1, central directory on disk 1)`,
    )
    expect(encrypted).toContain('加密')
    expect(spanned).toContain('分卷')
  })

  it('leaves a non-ingest error untouched', () => {
    // A 403/409/503 from the same endpoint is already a sentence; rewriting it
    // here would replace a precise message with a guess.
    const detail = "this content is already registered to skill 'other-skill'"
    expect(ingestErrorMessage(zh, detail)).toBe(detail)
    expect(ingestErrorMessage(en, detail)).toBe(detail)
  })

  it('frames an unrecognized ingest reason without hiding it', () => {
    // A reason this list has not learned yet must still be readable - it is what
    // the user would quote in a bug report.
    const rendered = ingestErrorMessage(zh, `${INGEST_ERROR_PREFIX}some brand new refusal`)
    expect(rendered).toContain('some brand new refusal')
    expect(rendered).not.toBe('ingest.unknown')
  })

  it('never renders a bare translation key, in either locale', () => {
    for (const t of [zh, en]) {
      for (const literal of INGEST_REASON_LITERALS) {
        const rendered = ingestErrorMessage(t, INGEST_ERROR_PREFIX + literal)
        expect(rendered.trim()).not.toBe('')
        expect(rendered).not.toMatch(/(^|\s)ingest\.[A-Za-z]/)
      }
    }
  })
})

// Same anti-drift posture as reasons.test.ts: a hand-written list of backend
// strings is exactly as blind as the code it is meant to catch changing. These
// read the real producers instead.
describe('the backend strings this module matches on', () => {
  it('all still appear in normalizer.py', () => {
    const source = readFileSync(NORMALIZER, 'utf-8')
    const missing = INGEST_REASON_LITERALS.filter((literal) => !source.includes(literal))
    expect(missing).toEqual([])
  })

  it('is prefixed exactly as both submission handlers build it', () => {
    // If either handler rewords its 400, every message silently reverts to raw
    // English - the bug this module was written to fix.
    for (const producer of PRODUCERS) {
      expect(readFileSync(producer, 'utf-8')).toContain(INGEST_ERROR_PREFIX)
    }
  })
})

describe('the ingest keys themselves', () => {
  it('exist in both locales', () => {
    const keys = Object.keys(TRANSLATIONS.zh).filter((key) => key.startsWith('ingest.'))
    expect(keys.length).toBeGreaterThan(0)
    for (const key of keys) {
      expect(TRANSLATIONS.en[key], `en is missing ${key}`).toBeTruthy()
    }
  })

  it('are all reachable from a real backend reason', () => {
    // A key nothing can produce is dead weight that reads as coverage.
    const reachable = new Set(
      INGEST_REASON_LITERALS.map((literal) => ingestErrorMessage(en, INGEST_ERROR_PREFIX + literal)),
    )
    reachable.add(ingestErrorMessage(en, `${INGEST_ERROR_PREFIX}unmatched`))
    for (const key of Object.keys(TRANSLATIONS.en).filter((k) => k.startsWith('ingest.'))) {
      const value = TRANSLATIONS.en[key]
      const rendered = key === 'ingest.unknown' ? value.replace('{detail}', 'unmatched') : value
      expect([...reachable], `${key} is unreachable`).toContain(rendered)
    }
  })
})
