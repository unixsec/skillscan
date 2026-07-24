import { useI18n } from '../i18n/I18nContext'

interface PagerProps {
  page: number
  pageCount: number
  onChange: (page: number) => void
}

// Traditional numbered-page pager for an already-loaded, client-side row set
// (mirrors useTableFilter's "already loaded, just paginate in the browser"
// scope - no new API surface).
export function Pager({ page, pageCount, onChange }: PagerProps) {
  const { t } = useI18n()
  if (pageCount <= 1) return null
  return (
    <div className="pager">
      <button type="button" onClick={() => onChange(page - 1)} disabled={page <= 1}>
        {t('pager.previous')}
      </button>
      <span className="pager-status">{t('pager.pageOf', { page, pageCount })}</span>
      <button type="button" onClick={() => onChange(page + 1)} disabled={page >= pageCount}>
        {t('pager.next')}
      </button>
    </div>
  )
}
