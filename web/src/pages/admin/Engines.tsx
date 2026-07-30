import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { BoolBadge, EngineHealthBadge } from '../../components/Badge'
import { useToast } from '../../components/Toast'
import { useI18n } from '../../i18n/I18nContext'
import {
  engineDurationHint,
  engineDurationLabel,
  engineVersionLabel,
  notReportedAttributionHint,
  notReportedAttributionLabel,
  windowObservation,
} from '../../engineHealth'
import type { EngineHealth, EngineHealthReport, EngineInfo } from '../../api/types'

function engineLabel(name: string, t: (key: string) => string): string {
  const translationKey = `engine.${name}`
  const translated = t(translationKey)
  return translated === translationKey ? name : translated
}

export function AdminEnginesPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, reload } = useApiData<{ engines: EngineInfo[] }>(
    () => api.get('/v1/admin/engines'),
    [],
  )
  // A SECOND request, deliberately. The listing above drives the enable/
  // disable buttons and must keep working when the orchestration database is
  // unreachable; folding the health read into it would turn a telemetry outage
  // into a dead engine console. `healthError` is therefore rendered as a note
  // beside the table and never handed to DataState, which would blank the page.
  const {
    data: health,
    error: healthError,
    loading: healthLoading,
  } = useApiData<EngineHealthReport>(() => api.get('/v1/admin/engines/health'), [])

  const healthByEngine = new Map<string, EngineHealth>(
    (health?.engines ?? []).map((entry) => [entry.name, entry]),
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

  // WHICH QUESTION THIS PAGE ANSWERS, said out loud rather than implied. The
  // health table is per-(scan, engine) - Task 12 drew that boundary explicitly
  // against the process-wide Prometheus metrics - so every count below is over
  // a bounded, stated window of recent scans, not over all history. Without
  // this line a reader cannot tell "0 failures across 50 scans" from "0
  // failures because nothing is retained", and a retention sweep would silently
  // read as engines that went quiet.
  function windowCaption(): string {
    if (healthLoading) return t('adminEngines.windowLoading')
    if (!health) return t('adminEngines.windowUnavailable')
    if (health.window.observed_scans === 0) {
      return t('adminEngines.windowEmpty', { requested: health.window.requested_scans })
    }
    return t('adminEngines.windowCaption', {
      observed: health.window.observed_scans,
      requested: health.window.requested_scans,
      from: health.window.started_at ? new Date(health.window.started_at).toLocaleString() : '?',
      to: health.window.ended_at ? new Date(health.window.ended_at).toLocaleString() : '?',
    })
  }

  return (
    <div>
      <h1>{t('adminEngines.title')}</h1>
      <p className="hint">{windowCaption()}</p>
      {healthError && (
        <p className="hint">{t('adminEngines.healthUnavailable', { message: healthError })}</p>
      )}
      <DataState loading={loading} error={error} empty={data?.engines.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('adminEngines.colName')}</th>
              <th>{t('adminEngines.colVersion')}</th>
              <th>{t('adminEngines.colRequired')}</th>
              <th>{t('adminEngines.colStatus')}</th>
              <th>{t('adminEngines.colLastResult')}</th>
              <th>{t('adminEngines.colLastDuration')}</th>
              <th>{t('adminEngines.colWindowCounts')}</th>
              <th>{t('common.action')}</th>
            </tr>
          </thead>
          <tbody>
            {data?.engines.map((e) => {
              // A miss is passed through as `undefined` on purpose - see
              // EngineHealthBadge: "no observation" is one of the states, not
              // an absence to be branched around.
              const h = healthByEngine.get(e.name)
              // 2026-07-30: `engineHealth.ts`'s renderers took `EngineHealth`
              // until per-scan coverage grew a second surface carrying the same
              // three values under unprefixed names. They now take the minimal
              // `EngineObservation` and this is the adapter - so the two
              // surfaces share ONE state machine, one badge-class table and one
              // duration three-state instead of drifting apart.
              // `engineDurationHint` below still takes the whole `EngineHealth`:
              // its window maximum has no per-scan counterpart.
              const observed = h && windowObservation(h)
              const attribution = notReportedAttributionLabel(t, observed)
              return (
                <tr key={e.name}>
                  <td>{engineLabel(e.name, t)}</td>
                  <td>{engineVersionLabel(t, e)}</td>
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
                    <EngineHealthBadge health={observed} />
                    {attribution && (
                      <div className="hint" title={notReportedAttributionHint(t, observed)}>
                        {attribution}
                      </div>
                    )}
                    {h?.last_error && h.last_report_state === 'reported' && (
                      <div className="hint">{h.last_error}</div>
                    )}
                  </td>
                  <td title={engineDurationHint(t, h)}>{engineDurationLabel(t, observed)}</td>
                  <td className="hint">
                    {h
                      ? t('adminEngines.countsCell', {
                          observed: h.observed_scans,
                          ok: h.counts.ok,
                          error: h.counts.error,
                          notReported: h.counts.not_reported,
                          unreadable: h.counts.unreadable,
                          partial: h.counts.partial,
                        })
                      : '—'}
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
              )
            })}
          </tbody>
        </table>
      </DataState>
      {health && health.unregistered_engines.length > 0 && (
        <p className="hint">
          {t('adminEngines.unregisteredEngines', {
            names: health.unregistered_engines.join(', '),
          })}
        </p>
      )}
    </div>
  )
}
