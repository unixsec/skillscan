import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n/I18nContext'

interface ToastItem {
  id: number
  kind: 'success' | 'error'
  message: string
}

interface ToastApi {
  success: (message: string) => void
  error: (message: string) => void
}

const ToastCtx = createContext<ToastApi | null>(null)
const AUTO_DISMISS_MS = 5000

export function ToastProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n()
  const [items, setItems] = useState<ToastItem[]>([])
  const nextId = useRef(0)

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((item) => item.id !== id))
  }, [])

  const push = useCallback(
    (kind: ToastItem['kind'], message: string) => {
      const id = nextId.current++
      setItems((prev) => [...prev, { id, kind, message }])
      window.setTimeout(() => dismiss(id), AUTO_DISMISS_MS)
    },
    [dismiss],
  )

  const api = useMemo<ToastApi>(
    () => ({
      success: (message: string) => push('success', message),
      error: (message: string) => push('error', message),
    }),
    [push],
  )

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="toast-viewport" role="status" aria-live="polite">
        {items.map((item) => (
          <div key={item.id} className={`toast toast-${item.kind}`}>
            <span>{item.message}</span>
            <button
              type="button"
              className="toast-dismiss"
              aria-label={t('common.dismiss')}
              onClick={() => dismiss(item.id)}
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastCtx)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
