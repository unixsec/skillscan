import type { ReactNode } from 'react'
import { useI18n } from '../i18n/I18nContext'

export function DataState({
  loading,
  error,
  empty,
  emptyLabel,
  children,
}: {
  loading: boolean
  error: string | null
  empty?: boolean
  emptyLabel?: string
  children: ReactNode
}) {
  const { t } = useI18n()
  if (loading) return <p className="hint">{t('common.loading')}</p>
  // SECURITY (INV-16): `error` always comes from `ApiError.detail`, itself
  // sourced from the backend's own JSON `detail` field - React's default
  // text-node escaping (no dangerouslySetInnerHTML anywhere in this app)
  // means even a maliciously-crafted detail string renders as inert text.
  if (error) return <p className="error">{t('common.error', { message: error })}</p>
  if (empty) return <p className="hint">{emptyLabel ?? t('common.noData')}</p>
  return <>{children}</>
}
