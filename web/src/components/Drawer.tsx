import { useEffect, useRef, type ReactNode } from 'react'
import { useI18n } from '../i18n/I18nContext'

interface DrawerProps {
  open: boolean
  title: string
  onClose: () => void
  children: ReactNode
}

export function Drawer({ open, title, onClose, children }: DrawerProps) {
  const { t } = useI18n()
  const panelRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<Element | null>(null)

  useEffect(() => {
    if (!open) return
    triggerRef.current = document.activeElement
    panelRef.current?.focus()

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      if (triggerRef.current instanceof HTMLElement) triggerRef.current.focus()
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      className="drawer-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div ref={panelRef} className="drawer-panel" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}>
        <div className="drawer-header">
          <h2 className="drawer-title">{title}</h2>
          <button type="button" className="drawer-close" onClick={onClose} aria-label={t('common.close')}>
            ×
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  )
}
