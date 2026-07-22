import { useMemo } from 'react'
import { api } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { BoolBadge } from '../components/Badge'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useI18n } from '../i18n/I18nContext'
import type { AuditEntrySummary } from '../api/types'

export function AuditPage() {
  const { t } = useI18n()
  const { data, loading, error } = useApiData<{
    chain_valid: boolean
    entries: AuditEntrySummary[]
  }>(() => api.get('/v1/audit'), [])
  const entries = useMemo(() => data?.entries ?? [], [data])
  const filterFields: FilterField<AuditEntrySummary>[] = useMemo(
    () => [
      { key: 'action', label: t('audit.colAction'), value: (row) => row.action },
      { key: 'operator', label: t('audit.colOperator'), value: (row) => row.operator },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(entries, filterFields)

  return (
    <div>
      <h1>{t('audit.title')}</h1>
      {data && (
        <p>
          {t('audit.chainStatus')}
          <BoolBadge value={!data.chain_valid} trueLabel={t('audit.tampered')} falseLabel={t('audit.valid')} />
        </p>
      )}
      <DataState loading={loading} error={error} empty={entries.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        <table>
          <thead>
            <tr>
              <th>{t('audit.colSeq')}</th>
              <th>{t('audit.colOperator')}</th>
              <th>{t('audit.colAction')}</th>
              <th>{t('audit.colWhen')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.seq}>
                <td>{e.seq}</td>
                <td>{e.operator}</td>
                <td>
                  <code>{e.action}</code>
                </td>
                <td>{new Date(e.chained_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
    </div>
  )
}
