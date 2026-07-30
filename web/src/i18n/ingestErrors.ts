// Translates the `POST /v1/scans` archive-rejection 400 into a sentence a
// person can act on.
//
// WHY THIS EXISTS. The backend detail is deliberately specific and deliberately
// English - it describes the caller's own upload (see gateway/router.py's
// comment on why returning it is safe), and it is the same string the API hands
// an integrator. The console used to render it VERBATIM in a toast, so a
// Chinese-locale user who uploaded the zip they downloaded from a marketplace
// got "invalid package archive: not a valid tar archive: file could not be
// opened successfully" and no idea what to do next. `reasons.ts` does not cover
// this: it translates `VerdictRow.reasons`, a different producer entirely.
//
// DESIGN. Only details carrying the ingest prefix are touched; every other
// ApiError on the submit path (403 ownership, 409 lifecycle, 503) is returned
// unchanged, because inventing a translation for a string this module does not
// recognize is how a wrong message gets shown confidently. An unrecognized
// ingest reason falls through to `ingest.unknown`, which frames the raw text
// rather than hiding it - a reason this list has not learned yet is still worth
// showing, and it is what the user would quote in a bug report.

import type { Translate } from './reasons'

// The exact prefix both submission handlers build their 400 detail with
// (`gateway/router.py` and `marketplace_api/router.py`:
// f"invalid package archive: {exc}"). Exported so `ingestErrors.test.ts` can
// assert it still appears in BOTH producers - if it is ever reworded, this
// whole module silently stops matching and every message reverts to raw
// English.
export const INGEST_ERROR_PREFIX = 'invalid package archive: '

// Substring -> translation key, in match order. Each substring is a literal
// from `services/engine_runner/normalizer.py`'s `UnpackRejected` messages, and
// the test asserts every one of them is still present in that file.
const INGEST_REASON_RULES: ReadonlyArray<readonly [string, string]> = [
  // Resource bounds. Ordered before the generic size wording so the more
  // specific total/ratio limits win.
  ['compression ratio', 'ingest.compressionBomb'],
  ['total uncompressed size', 'ingest.totalTooLarge'],
  ['archive size', 'ingest.archiveTooLarge'],
  ['entry count', 'ingest.tooManyEntries'],
  ['declared size', 'ingest.fileTooLarge'],
  ['exceeded max size while reading', 'ingest.fileTooLarge'],
  // Structure and container.
  ['encrypted', 'ingest.encryptedEntry'],
  ['spanned/multi-disk', 'ingest.spannedArchive'],
  ['symlink', 'ingest.linkEntry'],
  ['duplicate entry paths', 'ingest.duplicatePath'],
  ['directory prefix', 'ingest.pathCollision'],
  ['no regular files', 'ingest.noRegularFiles'],
  ['empty archive', 'ingest.emptyArchive'],
  // Unparseable.
  ['not a valid tar archive', 'ingest.unsupportedFormat'],
  ['not a valid zip archive', 'ingest.corruptZip'],
  ['end-of-central-directory', 'ingest.corruptZip'],
  // Paths.
  ['illegal path segment', 'ingest.illegalPath'],
  ['absolute path', 'ingest.illegalPath'],
  ['NUL byte', 'ingest.illegalPath'],
  ['path depth', 'ingest.pathTooDeep'],
  ['reduces to nothing', 'ingest.illegalPath'],
]

// Exported for the drift test only.
export const INGEST_REASON_LITERALS: readonly string[] = INGEST_REASON_RULES.map(
  ([literal]) => literal,
)

/**
 * Returns a human sentence for an ingest 400, or `detail` unchanged when it is
 * not one.
 */
export function ingestErrorMessage(t: Translate, detail: string): string {
  if (!detail.startsWith(INGEST_ERROR_PREFIX)) return detail
  const reason = detail.slice(INGEST_ERROR_PREFIX.length)
  for (const [literal, key] of INGEST_REASON_RULES) {
    if (reason.includes(literal)) return t(key)
  }
  return t('ingest.unknown', { detail: reason })
}
