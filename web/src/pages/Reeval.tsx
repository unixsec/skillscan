import { useMemo, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { BoolBadge } from '../components/Badge'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'
import { useToast } from '../components/Toast'
import type { DriftSummary, ReevalSkill } from '../api/types'

// `skill_lifecycle_event.reason`'s exact literal from apps/monolith/worker.py's
// `_quarantine_if_drifted` - "drift detected (SUP-05): baseline=<hash> !=
// current=<hash>". Parsed for a readable sentence; falls back to the raw
// string (never hidden) if the format ever drifts from this.
function driftEventLabel(t: (k: string, params?: Record<string, string>) => string, reason: string): string {
  const match = /^drift detected \(SUP-05\): baseline=(\S+) != current=(\S+)$/.exec(reason)
  if (!match) return reason
  return t('reeval.driftEventReason', {
    baseline: `${match[1].slice(0, 12)}…`,
    current: `${match[2].slice(0, 12)}…`,
  })
}

export function ReevalPage() {
  const { session } = useSession()
  const { t } = useI18n()
  const toast = useToast()
  const isAdmin = session?.roles.includes('admin') ?? false
  const { data, loading, error, reload } = useApiData<{
    current_toolchain_digest: string
    skills: ReevalSkill[]
    drift: DriftSummary
  }>(() => api.get('/v1/reeval'), [])
  const [busySkillId, setBusySkillId] = useState<string | null>(null)
  const skills = useMemo(() => data?.skills ?? [], [data])
  const driftSkills = useMemo(() => data?.drift.skills ?? [], [data])
  const driftEvents = useMemo(() => data?.drift.events ?? [], [data])
  const filterFields: FilterField<ReevalSkill>[] = useMemo(
    () => [
      {
        key: 'stale',
        label: t('reeval.colStatus'),
        value: (row) => (row.stale ? 'stale' : 'current'),
        renderOption: (v) => (v === 'stale' ? t('reeval.stale') : t('reeval.current')),
      },
      {
        key: 'trust_tier',
        label: t('reeval.colTrustTier'),
        value: (row) => row.trust_tier,
        renderOption: (v) => {
          const key = `trustTier.${v}`
          const translated = t(key)
          return translated === key ? v : translated
        },
      },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(skills, filterFields)

  async function trigger(skillId: string) {
    setBusySkillId(skillId)
    try {
      await api.post(`/v1/reeval/${skillId}`)
      reload()
      toast.success(t('reeval.triggerSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('reeval.triggerFailed'))
    } finally {
      setBusySkillId(null)
    }
  }

  return (
    <div>
      <h1>{t('reeval.title')}</h1>

      <h2>{t('reeval.toolchainHeading')}</h2>
      <p className="hint">{t('reeval.toolchainExplanation')}</p>
      {data && (
        <p className="hint">
          {t('reeval.currentDigest', { digest: `${data.current_toolchain_digest.slice(0, 16)}…` })}
        </p>
      )}
      <DataState loading={loading} error={error} empty={skills.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        <table>
          <thead>
            <tr>
              <th>{t('reeval.colSkillId')}</th>
              <th>{t('reeval.colTrustTier')}</th>
              <th>{t('reeval.colRecordedDigest')}</th>
              <th>{t('reeval.colStatus')}</th>
              {isAdmin && <th>{t('common.action')}</th>}
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={`${s.skill_id}:${s.content_hash}`}>
                <td>{s.skill_id}</td>
                <td>{s.trust_tier}</td>
                <td>
                  <code>{s.recorded_toolchain_digest.slice(0, 16)}…</code>
                </td>
                <td>
                  <BoolBadge value={s.stale} trueLabel={t('reeval.stale')} falseLabel={t('reeval.current')} />
                </td>
                {isAdmin && (
                  <td>
                    <button disabled={busySkillId === s.skill_id} onClick={() => trigger(s.skill_id)}>
                      {t('reeval.trigger')}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>

      <h2 style={{ marginTop: '2rem' }}>{t('reeval.driftHeading')}</h2>
      <p className="hint">{t('reeval.driftExplanation')}</p>

      <h3>{t('reeval.driftLiveHeading')}</h3>
      <p className="hint">{t('reeval.driftLiveExplanation')}</p>
      <DataState loading={loading} error={error} empty={driftSkills.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('reeval.colSkillId')}</th>
              <th>{t('reeval.colBaselineHash')}</th>
              <th>{t('reeval.colLatestHash')}</th>
              <th>{t('reeval.colDriftStatus')}</th>
            </tr>
          </thead>
          <tbody>
            {driftSkills.map((s) => (
              <tr key={s.skill_id}>
                <td>{s.skill_id}</td>
                <td>
                  <code>{s.baseline_content_hash.slice(0, 12)}…</code>
                </td>
                <td>
                  {s.latest_content_hash ? (
                    <code>{s.latest_content_hash.slice(0, 12)}…</code>
                  ) : (
                    <span className="hint">{t('reeval.noVersionRecorded')}</span>
                  )}
                </td>
                <td>
                  <BoolBadge value={s.drifted} trueLabel={t('reeval.drifted')} falseLabel={t('reeval.notDrifted')} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>

      <h3 style={{ marginTop: '1.5rem' }}>{t('reeval.driftEventsHeading')}</h3>
      <p className="hint">{t('reeval.driftEventsExplanation')}</p>
      <DataState loading={loading} error={error} empty={driftEvents.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('reeval.colSkillId')}</th>
              <th>{t('reeval.colOccurredAt')}</th>
              <th>{t('reeval.colDriftDetail')}</th>
            </tr>
          </thead>
          <tbody>
            {driftEvents.map((e, i) => (
              <tr key={`${e.skill_id}:${e.occurred_at}:${i}`}>
                <td>{e.skill_id}</td>
                <td>{new Date(e.occurred_at).toLocaleString()}</td>
                <td>{driftEventLabel(t, e.reason)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
    </div>
  )
}
