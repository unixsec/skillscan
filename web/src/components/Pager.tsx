import { useI18n } from '../i18n/I18nContext'

interface PagerProps {
  page: number
  // The total number of pages when it is KNOWN - i.e. the whole row set is
  // already in the browser and can be counted (Reports). `null` means the
  // caller pages against the server, which returns rows but no total, so the
  // only truthful thing to say is which page you are on; `hasNext` then
  // decides whether there is another one.
  pageCount: number | null
  // Consulted only when `pageCount` is null.
  hasNext?: boolean
  onChange: (page: number) => void
}

// Numbered-page pager, for both an already-loaded client-side row set and a
// server-side offset window whose total is unknown. Deliberately does NOT
// invent a page count in the second case: rendering "Page 1 of 2" over a
// 4000-row scan table because only one more page was probed would be a lie the
// user has no way to detect.
export function Pager({ page, pageCount, hasNext, onChange }: PagerProps) {
  const { t } = useI18n()
  const totalKnown = pageCount !== null
  const canPrev = page > 1
  const canNext = totalKnown ? page < pageCount : hasNext === true
  // Nowhere to go in either direction - the pager is noise.
  if (!canPrev && !canNext) return null
  return (
    <div className="pager">
      <button type="button" onClick={() => onChange(page - 1)} disabled={!canPrev}>
        {t('pager.previous')}
      </button>
      <span className="pager-status">
        {totalKnown ? t('pager.pageOf', { page, pageCount }) : t('pager.pageN', { page })}
      </span>
      <button type="button" onClick={() => onChange(page + 1)} disabled={!canNext}>
        {t('pager.next')}
      </button>
    </div>
  )
}

interface CursorPagerProps {
  // Already-rendered status text: the caller owns what its cursor MEANS (an
  // audit seq range, say) - this component only owns the navigation.
  status: string
  hasOlder: boolean
  hasNewer: boolean
  onOlder: () => void
  onNewer: () => void
}

// Pager for an endpoint with CURSOR semantics rather than offset semantics -
// today, `GET /v1/audit`, whose only positional parameter is `since_seq`.
//
// Page numbers are the wrong model there twice over: the ledger is append-only,
// so "page 3 from the end" names different rows every time an entry is written,
// and the endpoint cannot answer "how many pages" without counting the whole
// chain. Older/newer is what the API actually offers, so it is what the UI
// offers.
export function CursorPager({ status, hasOlder, hasNewer, onOlder, onNewer }: CursorPagerProps) {
  const { t } = useI18n()
  if (!hasOlder && !hasNewer) return null
  return (
    <div className="pager">
      <button type="button" onClick={onOlder} disabled={!hasOlder}>
        {t('pager.older')}
      </button>
      <span className="pager-status">{status}</span>
      <button type="button" onClick={onNewer} disabled={!hasNewer}>
        {t('pager.newer')}
      </button>
    </div>
  )
}
