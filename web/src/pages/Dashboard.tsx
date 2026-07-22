import { api } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { SummaryGrid } from '../components/SummaryGrid'
import type { Report } from '../api/types'
import { useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'

const VERDICT_ORDER = ['BLOCK', 'REVIEW', 'PASS'] as const
const VERDICT_TREND_VAR: Record<(typeof VERDICT_ORDER)[number], string> = {
  BLOCK: 'var(--critical)',
  REVIEW: 'var(--medium)',
  PASS: 'var(--ok)',
}

const CHART = { width: 640, height: 200, padX: 40, padTop: 20, padBottom: 32 }

function groupByDate(
  rows: Record<string, unknown>[],
): { dates: string[]; byDate: Map<string, Partial<Record<string, number>>> } {
  const byDate = new Map<string, Partial<Record<string, number>>>()
  for (const row of rows) {
    const date = String(row.date)
    const verdict = String(row.verdict)
    const count = Number(row.count) || 0
    if (!byDate.has(date)) byDate.set(date, {})
    byDate.get(date)![verdict] = count
  }
  const dates = [...byDate.keys()].sort().slice(-7)
  return { dates, byDate }
}

function TrendChart({ rows }: { rows: Record<string, unknown>[] }) {
  const { t } = useI18n()
  const { dates, byDate } = groupByDate(rows)
  if (dates.length === 0) {
    return <p className="hint">{t('dashboard.noTrendData')}</p>
  }
  const maxCount = Math.max(
    ...dates.flatMap((date) => VERDICT_ORDER.map((v) => byDate.get(date)?.[v] ?? 0)),
    1,
  )
  const plotWidth = CHART.width - CHART.padX * 2
  const plotHeight = CHART.height - CHART.padTop - CHART.padBottom
  const x = (i: number) =>
    dates.length === 1 ? CHART.padX + plotWidth / 2 : CHART.padX + (i / (dates.length - 1)) * plotWidth
  const y = (count: number) => CHART.padTop + plotHeight - (count / maxCount) * plotHeight

  return (
    <div>
      <svg
        viewBox={`0 0 ${CHART.width} ${CHART.height}`}
        role="img"
        aria-label={t('dashboard.trendTitle')}
        style={{ width: '100%', height: 'auto' }}
      >
        {[0, 0.5, 1].map((frac) => {
          const gy = y(maxCount * frac)
          return (
            <g key={frac}>
              <line
                x1={CHART.padX}
                x2={CHART.width - CHART.padX}
                y1={gy}
                y2={gy}
                stroke="var(--border-soft)"
                strokeDasharray="4 4"
              />
              <text x={CHART.padX - 8} y={gy + 4} textAnchor="end" fontSize="11" fill="var(--text-soft)">
                {Math.round(maxCount * frac)}
              </text>
            </g>
          )
        })}
        {dates.map((date, i) => (
          <text key={date} x={x(i)} y={CHART.height - 8} textAnchor="middle" fontSize="11" fill="var(--text-soft)">
            {date.slice(5)}
          </text>
        ))}
        {VERDICT_ORDER.map((v) => {
          const color = VERDICT_TREND_VAR[v]
          const points = dates.map((date, i) => ({
            px: x(i),
            py: y(byDate.get(date)?.[v] ?? 0),
            count: byDate.get(date)?.[v] ?? 0,
          }))
          return (
            <g key={v}>
              <polyline
                points={points.map((p) => `${p.px},${p.py}`).join(' ')}
                fill="none"
                stroke={color}
                strokeWidth="1.5"
              />
              {points.map((p, i) => (
                <circle key={`${v}-${dates[i]}`} cx={p.px} cy={p.py} r="2.5" fill={color}>
                  <title>{`${dates[i]} ${t(`verdict.${v}`)}: ${p.count}`}</title>
                </circle>
              ))}
            </g>
          )
        })}
      </svg>
      <div className="trend-legend">
        {VERDICT_ORDER.map((v) => (
          <span key={v} className="trend-legend-item">
            <span className="trend-legend-dot" style={{ background: VERDICT_TREND_VAR[v] }} />
            {t(`verdict.${v}`)}
          </span>
        ))}
      </div>
    </div>
  )
}

function EngineCoverageCards({ rows }: { rows: Record<string, unknown>[] }) {
  const { t } = useI18n()
  if (rows.length === 0) return <p className="hint">{t('dashboard.noEngineData')}</p>
  return (
    <div>
      {rows.map((row) => {
        const name = String(row.name)
        const required = Boolean(row.required)
        const disabled = Boolean(row.disabled)
        const adapterStatus = String(row.adapter_status ?? '')
        const badgeClass = disabled ? 'badge-block' : required ? 'badge-review' : 'badge-neutral'
        const statusLabel = disabled
          ? t('dashboard.engineDisabled')
          : required
            ? t('dashboard.engineRequired')
            : t('dashboard.engineOptional')
        return (
          <div className="entity-card" key={name}>
            <div className="entity-card-top">
              <span className="entity-card-name">{name}</span>
              <span className={`badge ${badgeClass}`}>{statusLabel}</span>
            </div>
            <div className="entity-card-meta">{adapterStatus}</div>
          </div>
        )
      })}
    </div>
  )
}

export function DashboardPage() {
  const { session } = useSession()
  const { t } = useI18n()
  const summaryData = useApiData<Report>(
    () => api.get<Report>('/v1/reports?template=executive_summary'),
    [],
  )
  const trendData = useApiData<Report>(() => api.get<Report>('/v1/reports?template=risk_trend'), [])
  const engineData = useApiData<Report>(
    () => api.get<Report>('/v1/reports?template=engine_coverage'),
    [],
  )

  return (
    <div>
      <h1>{t('dashboard.title')}</h1>
      {session && <p className="hint">{t('dashboard.signedInAs', { subject: session.subject })}</p>}

      <DataState loading={summaryData.loading} error={summaryData.error}>
        {summaryData.data && <SummaryGrid summary={summaryData.data.summary} />}
      </DataState>

      <div className="dashboard-grid">
        <div className="card">
          <div className="panel-head">
            <h2>{t('dashboard.trendTitle')}</h2>
            <span className="panel-pill">{t('dashboard.trendPill')}</span>
          </div>
          <DataState loading={trendData.loading} error={trendData.error}>
            {trendData.data && <TrendChart rows={trendData.data.rows} />}
          </DataState>
        </div>

        <div className="card">
          <div className="panel-head">
            <h2>{t('dashboard.engineCoverageTitle')}</h2>
            <span className="panel-pill">{t('dashboard.engineCoveragePill')}</span>
          </div>
          <DataState loading={engineData.loading} error={engineData.error}>
            {engineData.data && <EngineCoverageCards rows={engineData.data.rows} />}
          </DataState>
        </div>
      </div>

      <p className="hint">
        {t('dashboard.summaryHint', { count: summaryData.data?.rows.length ?? 0 })}
      </p>
    </div>
  )
}
