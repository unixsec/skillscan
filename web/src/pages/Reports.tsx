import { useMemo, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { SummaryGrid } from '../components/SummaryGrid'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'
import { useToast } from '../components/Toast'
import type { Report, ReportSchedule } from '../api/types'

const TEMPLATES = [
  'executive_summary',
  'compliance_status',
  'risk_trend',
  'engine_coverage',
  'exception_audit',
]

function rowKeyLabel(key: string, t: (k: string) => string): string {
  const translationKey = `row.${key}`
  const translated = t(translationKey)
  return translated === translationKey ? key.replaceAll('_', ' ') : translated
}

// `since`/`until` are plain `<input type="date">` values (empty string when
// unset). FastAPI parses a bare "YYYY-MM-DD" as midnight of that day, so
// `until` is inclusive only through 00:00 of the chosen day; the backend has
// always accepted this shape, the UI just never exposed it (2026-07-14,
// item #10).
function buildReportQuery(
  template: string,
  since: string,
  until: string,
  extra?: Record<string, string>,
): string {
  const params = new URLSearchParams({ template })
  if (since) params.set('since', since)
  if (until) params.set('until', until)
  for (const [k, v] of Object.entries(extra ?? {})) params.set(k, v)
  return params.toString()
}

export function ReportsPage() {
  const { session } = useSession()
  const { t } = useI18n()
  const toast = useToast()
  const isAdmin = session?.roles.includes('admin') ?? false
  const [template, setTemplate] = useState(TEMPLATES[0])
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const { data, loading, error } = useApiData<Report>(
    () => api.get(`/v1/reports?${buildReportQuery(template, since, until)}`),
    [template, since, until],
  )
  const { data: scheduleData, reload: reloadSchedules } = useApiData<{ schedules: ReportSchedule[] }>(
    () => api.get('/v1/reports/schedule'),
    [],
  )
  const [scheduleForm, setScheduleForm] = useState({ cron: '0 6 * * *', targets: '' })
  const [exporting, setExporting] = useState<string | null>(null)

  async function exportReport(format: 'csv' | 'pdf') {
    setExporting(format)
    try {
      await api.download(
        `/v1/reports?${buildReportQuery(template, since, until, { export: format })}`,
        `${template}.${format}`,
      )
      toast.success(t('reports.exportSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('reports.exportFailed'))
    } finally {
      setExporting(null)
    }
  }

  async function createSchedule(event: React.FormEvent) {
    event.preventDefault()
    try {
      await api.post('/v1/reports/schedule', {
        template,
        cron: scheduleForm.cron,
        targets: scheduleForm.targets
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      })
      reloadSchedules()
      toast.success(t('reports.scheduleSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('reports.scheduleFailed'))
    }
  }

  const rows = useMemo(() => data?.rows ?? [], [data])
  const rowKeys = useMemo(() => (rows[0] ? Object.keys(rows[0]) : []), [rows])
  // Offer a dropdown for every column with a small, low-cardinality set of
  // distinct values (categorical columns like verdict/severity/category/
  // state), skipping free-form/high-cardinality ones (hashes, ids, dates).
  const filterFields: FilterField<Record<string, unknown>>[] = useMemo(() => {
    return rowKeys
      .map((key) => ({
        key,
        distinct: new Set(rows.map((r) => String(r[key] ?? ''))),
      }))
      .filter(({ distinct }) => distinct.size >= 2 && distinct.size <= 12)
      .map(({ key }) => ({
        key,
        label: rowKeyLabel(key, t),
        value: (row: Record<string, unknown>) => String(row[key] ?? ''),
        renderOption: (v: string) => {
          const verdictKey = `verdict.${v}`
          const translated = t(verdictKey)
          return translated === verdictKey ? v : translated
        },
      }))
  }, [rowKeys, rows, t])
  const {
    filtered: filteredRows,
    options,
    selected,
    setSelected,
  } = useTableFilter(rows, filterFields)

  return (
    <div>
      <h1>{t('reports.title')}</h1>
      <form className="inline-form" onSubmit={(e) => e.preventDefault()}>
        <label>
          {t('reports.template')}
          <select value={template} onChange={(e) => setTemplate(e.target.value)}>
            {TEMPLATES.map((tpl) => (
              <option key={tpl} value={tpl}>
                {t(`reports.template.${tpl}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('reports.since')}
          <input type="date" value={since} max={until || undefined} onChange={(e) => setSince(e.target.value)} />
        </label>
        <label>
          {t('reports.until')}
          <input type="date" value={until} min={since || undefined} onChange={(e) => setUntil(e.target.value)} />
        </label>
        {(since || until) && (
          <button type="button" onClick={() => { setSince(''); setUntil('') }}>
            {t('reports.clearRange')}
          </button>
        )}
        <button type="button" onClick={() => exportReport('csv')} disabled={exporting !== null}>
          {exporting === 'csv' ? t('reports.exporting') : t('reports.exportCsv')}
        </button>
        <button type="button" onClick={() => exportReport('pdf')} disabled={exporting !== null}>
          {exporting === 'pdf' ? t('reports.exporting') : t('reports.exportPdf')}
        </button>
      </form>
      <DataState loading={loading} error={error}>
        {data && (
          <>
            <SummaryGrid summary={data.summary} />
            {rows.length > 0 && (
              <>
                <TableFilterBar
                  fields={filterFields}
                  options={options}
                  selected={selected}
                  onChange={setSelected}
                />
                <p className="hint">
                  {t('reports.rowCount', { shown: filteredRows.length, total: rows.length })}
                </p>
                <table>
                  <thead>
                    <tr>
                      {rowKeys.map((k) => (
                        <th key={k}>{rowKeyLabel(k, t)}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRows.slice(0, 100).map((row, i) => (
                      <tr key={i}>
                        {rowKeys.map((k) => (
                          <td key={k}>{String(row[k] ?? '')}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </>
        )}
      </DataState>

      {isAdmin && (
        <>
          <h2>{t('reports.schedules')}</h2>
          <p className="hint">{t('reports.scheduleNotWiredNotice')}</p>
          <form className="inline-form" onSubmit={createSchedule}>
            <label>
              {t('reports.cron')}
              <input
                value={scheduleForm.cron}
                onChange={(e) => setScheduleForm({ ...scheduleForm, cron: e.target.value })}
              />
            </label>
            <label>
              {t('reports.targets')}
              <input
                value={scheduleForm.targets}
                onChange={(e) => setScheduleForm({ ...scheduleForm, targets: e.target.value })}
                placeholder={t('reports.targetsPlaceholder')}
              />
            </label>
            <button type="submit" className="primary">
              {t('reports.schedule', { template })}
            </button>
          </form>
          <table>
            <thead>
              <tr>
                <th>{t('reports.colTemplate')}</th>
                <th>{t('reports.colCron')}</th>
                <th>{t('reports.colTargets')}</th>
                <th>{t('reports.colCreatedBy')}</th>
              </tr>
            </thead>
            <tbody>
              {scheduleData?.schedules.map((s) => (
                <tr key={s.id}>
                  <td>{s.template}</td>
                  <td>
                    <code>{s.cron}</code>
                  </td>
                  <td>{s.targets.join(', ')}</td>
                  <td>{s.created_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}
