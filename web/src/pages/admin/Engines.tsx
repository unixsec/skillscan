import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { BoolBadge } from '../../components/Badge'
import { useToast } from '../../components/Toast'
import { useI18n } from '../../i18n/I18nContext'
import type { EngineInfo } from '../../api/types'

export function AdminEnginesPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, reload } = useApiData<{ engines: EngineInfo[] }>(
    () => api.get('/v1/admin/engines'),
    [],
  )

  async function toggle(name: string, enabled: boolean) {
    try {
      await api.patch(`/v1/admin/engines/${name}`, { enabled: !enabled })
      reload()
      toast.success(enabled ? t('adminEngines.disableSucceeded') : t('adminEngines.enableSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminEngines.toggleFailed'))
    }
  }

  return (
    <div>
      <h1>{t('adminEngines.title')}</h1>
      <DataState loading={loading} error={error} empty={data?.engines.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('adminEngines.colName')}</th>
              <th>{t('adminEngines.colVersion')}</th>
              <th>{t('adminEngines.colRequired')}</th>
              <th>{t('adminEngines.colStatus')}</th>
              <th>{t('common.action')}</th>
            </tr>
          </thead>
          <tbody>
            {data?.engines.map((e) => (
              <tr key={e.name}>
                <td>{e.name}</td>
                <td>{e.version ?? '—'}</td>
                <td>
                  <BoolBadge
                    value={e.required}
                    trueLabel={t('adminEngines.required')}
                    falseLabel={t('adminEngines.optional')}
                  />
                </td>
                <td>
                  <BoolBadge
                    value={!e.enabled}
                    trueLabel={t('adminEngines.disabled')}
                    falseLabel={t('adminEngines.enabled')}
                  />
                </td>
                <td>
                  <button
                    disabled={e.required && e.enabled}
                    title={e.required && e.enabled ? t('adminEngines.cannotDisableRequired') : ''}
                    onClick={() => toggle(e.name, e.enabled)}
                  >
                    {e.enabled ? t('adminEngines.disable') : t('adminEngines.enable')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
    </div>
  )
}
