import { useMemo } from 'react'
import { api } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useI18n } from '../i18n/I18nContext'
import type { ReconciliationOutcome } from '../api/types'

// Enum values from the backend (reeval/reconciliation.py ReconciliationResult
// and the poll/push source field) rendered through i18n, falling back to the
// raw value for anything a future backend version might add.
function enumLabel(t: (k: string) => string, namespace: string, value: string): string {
  const key = `${namespace}.${value}`
  const translated = t(key)
  return translated === key ? value : translated
}

// 2026-07-14 (item #9): SKILLSCAN_RECONCILIATION_POLL_ENABLED/PUSH_ENABLED
// are both false by default (no real marketplace configured) - this table is
// otherwise empty on a fresh deployment. Rows seeded for UI validation (see
// scratchpad/seed_demo_reconciliation.py; result classification computed by
// the real reeval.reconciliation.reconcile(), never hand-typed) all use this
// skill_id prefix so they can never collide with a real skill_id and stay
// visibly tagged even if genuine reconciliation data appears later.
const DEMO_SKILL_ID_PREFIX = 'demo-reconciliation-'

function isDemoRow(o: ReconciliationOutcome): boolean {
  return o.skill_id?.startsWith(DEMO_SKILL_ID_PREFIX) ?? false
}

export function ReconciliationPage() {
  const { t } = useI18n()
  const { data, loading, error } = useApiData<{ outcomes: ReconciliationOutcome[] }>(
    () => api.get('/v1/reconciliation'),
    [],
  )
  const outcomes = useMemo(() => data?.outcomes ?? [], [data])
  const hasDemoRows = useMemo(() => outcomes.some(isDemoRow), [outcomes])
  const filterFields: FilterField<ReconciliationOutcome>[] = useMemo(
    () => [
      {
        key: 'result',
        label: t('reconciliation.colResult'),
        value: (row) => row.result,
        renderOption: (v) => enumLabel(t, 'reconciliation.result', v),
      },
      {
        key: 'source',
        label: t('reconciliation.colSource'),
        value: (row) => row.source,
        renderOption: (v) => enumLabel(t, 'reconciliation.source', v),
      },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(outcomes, filterFields)

  return (
    <div>
      <h1>{t('reconciliation.title')}</h1>
      <p className="hint">{t('reconciliation.description')}</p>
      {hasDemoRows && <p className="hint">{t('reconciliation.demoNotice')}</p>}
      <DataState loading={loading} error={error} empty={outcomes.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        <table>
          <thead>
            <tr>
              <th>{t('reconciliation.colSkillId')}</th>
              <th>{t('reconciliation.colContentHash')}</th>
              <th>{t('reconciliation.colResult')}</th>
              <th>{t('reconciliation.colSource')}</th>
              <th>{t('reconciliation.colDetected')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((o, i) => (
              <tr key={i}>
                <td>
                  {o.skill_id ?? '—'}
                  {isDemoRow(o) && (
                    <>
                      {' '}
                      <span className="badge badge-neutral">{t('reconciliation.demoTag')}</span>
                    </>
                  )}
                </td>
                <td>{o.content_hash ? <code>{o.content_hash.slice(0, 16)}…</code> : '—'}</td>
                <td>
                  <span className={o.result === 'MATCH' ? 'badge badge-pass' : 'badge badge-block'}>
                    {enumLabel(t, 'reconciliation.result', o.result)}
                  </span>
                </td>
                <td>{enumLabel(t, 'reconciliation.source', o.source)}</td>
                <td>{new Date(o.detected_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
    </div>
  )
}
