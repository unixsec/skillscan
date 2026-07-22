import { useState } from 'react'
import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { BoolBadge } from '../../components/Badge'
import { useI18n } from '../../i18n/I18nContext'
import { useToast } from '../../components/Toast'
import type { BreakGlassStatus } from '../../api/types'

export function AdminBreakGlassPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, reload } = useApiData<BreakGlassStatus>(
    () => api.get('/v1/admin/breakglass'),
    [],
  )
  const [secondActivator, setSecondActivator] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function activate(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    try {
      await api.post('/v1/admin/breakglass/activate', {
        second_activator: secondActivator,
        totp_code: totpCode,
      })
      setSecondActivator('')
      setTotpCode('')
      reload()
      toast.success(t('adminBreakglass.activateSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminBreakglass.activationFailed'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <h1>{t('adminBreakglass.title')}</h1>
      <p className="hint">{t('adminBreakglass.description')}</p>
      <DataState loading={loading} error={error}>
        {data && (
          <div className="summary-grid">
            <div className="summary-stat">
              <div className="value">
                <BoolBadge
                  value={!data.enabled}
                  trueLabel={t('adminBreakglass.notConfigured')}
                  falseLabel={t('adminBreakglass.configured')}
                />
              </div>
              <div className="label">{t('adminBreakglass.configuredStatLabel')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">
                <BoolBadge
                  value={data.armed}
                  trueLabel={t('adminBreakglass.armed')}
                  falseLabel={t('adminBreakglass.notArmed')}
                />
              </div>
              <div className="label">{t('adminBreakglass.armedStatLabel')}</div>
            </div>
          </div>
        )}
      </DataState>
      {data?.enabled && (
        <>
          <h2>{t('adminBreakglass.activate')}</h2>
          <form className="inline-form" onSubmit={activate}>
            <label>
              {t('adminBreakglass.secondActivator')}
              <input
                value={secondActivator}
                onChange={(e) => setSecondActivator(e.target.value)}
                required
              />
            </label>
            <label>
              {t('login.totpCode')}
              <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} required />
            </label>
            <button type="submit" className="primary" disabled={submitting}>
              {submitting ? t('adminBreakglass.activating') : t('adminBreakglass.activate')}
            </button>
          </form>
        </>
      )}
    </div>
  )
}
