import { useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { SeverityBadge, VerdictBadge } from '../components/Badge'
import { useI18n } from '../i18n/I18nContext'
import type { Finding, ScanDetail } from '../api/types'

// The 8 detection categories (SRS §3.3 "8类61项") - shown in a FIXED, complete
// order regardless of which ones actually have findings, so the by-category
// view is a full situational overview ("态势"), not just a list of hits.
const ALL_CATEGORIES = [
  'instruction',
  'code',
  'data_credential',
  'network_intel',
  'permission',
  'file_package',
  'supply_chain',
  'bundled_component',
]

interface ModuleRow {
  key: string
  label: string
  version?: string
  count: number
  maxSeverity: number | null
}

function maxSeverityOf(findings: Finding[]): number | null {
  if (findings.length === 0) return null
  return Math.max(...findings.map((f) => f.severity))
}

function engineLabel(name: string, t: (key: string) => string): string {
  const translationKey = `engine.${name}`
  const translated = t(translationKey)
  return translated === translationKey ? name : translated
}

function byEngine(data: ScanDetail, t: (key: string) => string): ModuleRow[] {
  const engines = new Map<string, string>() // name -> version
  for (const [name, version] of data.provenance) {
    engines.set(name, version)
  }
  // a finding's source_engine might not appear in provenance (e.g. an
  // in-house detector not modeled as a vendored "engine") - include those too
  // so no real finding is silently dropped from this module view.
  for (const f of data.findings) {
    if (!engines.has(f.source_engine)) engines.set(f.source_engine, '')
  }
  return [...engines.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, version]) => {
      const findings = data.findings.filter((f) => f.source_engine === name)
      return {
        key: name,
        label: engineLabel(name, t),
        version,
        count: findings.length,
        maxSeverity: maxSeverityOf(findings),
      }
    })
}

function byCategory(data: ScanDetail, t: (key: string) => string): ModuleRow[] {
  return ALL_CATEGORIES.map((category) => {
    const findings = data.findings.filter((f) => f.category === category)
    return {
      key: category,
      label: t(`category.${category}`),
      count: findings.length,
      maxSeverity: maxSeverityOf(findings),
    }
  })
}

function ModuleTable({ rows, moduleLabel, versionLabel }: { rows: ModuleRow[]; moduleLabel: string; versionLabel?: string }) {
  const { t } = useI18n()
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{moduleLabel}</th>
            {versionLabel && <th>{versionLabel}</th>}
            <th>{t('scanDetail.colFindingCount')}</th>
            <th>{t('scanDetail.colMaxSeverity')}</th>
            <th>{t('scanDetail.colStatus')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td>{row.label}</td>
              {versionLabel && (
                <td>
                  <code>{row.version || '—'}</code>
                </td>
              )}
              <td>{row.count}</td>
              <td>
                <SeverityBadge severity={row.maxSeverity} />
              </td>
              <td>
                <span className={row.count === 0 ? 'badge badge-pass' : 'badge badge-block'}>
                  {row.count === 0 ? t('scanDetail.statusPass') : t('scanDetail.statusFail')}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function ScanDetailContent({ scanId }: { scanId: string }) {
  const { t } = useI18n()
  const { data, loading, error } = useApiData<ScanDetail>(
    () => api.get(`/v1/scans/${scanId}`),
    [scanId],
  )
  // required_ok is null EXCLUSIVELY when no ScanResultRow exists at all (GET
  // /v1/scans/{id}'s own fallback) - the poison-pill/dead-letter path
  // (orchestration.service._dead_letter_and_decide) records a real, signed
  // verdict WITHOUT ever aggregating real engine findings, since there's
  // genuinely nothing to aggregate. Rendering the by-engine/by-category
  // breakdown and an empty findings list in that case showed everything as
  // "0 findings = PASS", directly contradicting the BLOCK verdict sitting
  // right above it - found live via scan 87ad9d0e-d430-40f1-8ffd-50219cba4465.
  const neverScored = data != null && data.required_ok === null && data.verdict !== null

  return (
    <DataState loading={loading} error={error}>
      {data && (
        <>
          <div className="summary-grid">
            <div className="summary-stat">
              <div className="value">
                {t(`scanState.${data.state}`) === `scanState.${data.state}`
                  ? data.state
                  : t(`scanState.${data.state}`)}
              </div>
              <div className="label">{t('scanDetail.state')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">
                <VerdictBadge verdict={data.verdict} />
              </div>
              <div className="label">{t('scanDetail.verdict')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">{data.submitter}</div>
              <div className="label">{t('scanDetail.submitter')}</div>
            </div>
          </div>

          {data.required_ok === false && (
            <p className="error">{t('scanDetail.requiredEngineWarning')}</p>
          )}

          {data.reasons.length > 0 && (
            <>
              <h2>{t('scanDetail.reasons')}</h2>
              <ul>
                {data.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </>
          )}

          <h2>{t('scanDetail.byModule')}</h2>
          {neverScored ? (
            <p className="error">{t('scanDetail.neverScoredNotice')}</p>
          ) : (
            <>
              <p className="hint">{t('scanDetail.byModuleHint')}</p>
              <h2 style={{ fontSize: '0.95rem' }}>{t('scanDetail.byEngine')}</h2>
              <ModuleTable
                rows={byEngine(data, t)}
                moduleLabel={t('scanDetail.colModule')}
                versionLabel={t('scanDetail.colEngineVersion')}
              />
              <h2 style={{ fontSize: '0.95rem' }}>{t('scanDetail.byCategory')}</h2>
              <ModuleTable rows={byCategory(data, t)} moduleLabel={t('scanDetail.colModule')} />
            </>
          )}

          {!neverScored && (
            <>
              <h2>{t('scanDetail.findings', { count: data.findings.length })}</h2>
              {data.findings.length === 0 ? (
                <p className="hint">{t('scanDetail.noFindings')}</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>{t('scanDetail.colRule')}</th>
                        <th>{t('scanDetail.colTitle')}</th>
                        <th>{t('scanDetail.colSeverity')}</th>
                        <th>{t('scanDetail.colPath')}</th>
                        <th>{t('scanDetail.colEvidence')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.findings.map((f, i) => (
                        <tr key={i}>
                          <td>
                            <code>{f.rule_id}</code>
                          </td>
                          <td>{f.title}</td>
                          <td>
                            <SeverityBadge severity={f.severity} />
                          </td>
                          <td>
                            {f.file_path ?? '—'}
                            {f.start_line ? `:${f.start_line}` : ''}
                          </td>
                          <td>{f.evidence_redacted || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </>
      )}
    </DataState>
  )
}

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const { t } = useI18n()
  return (
    <div>
      <h1>{t('scanDetail.title', { scanId: scanId ?? '' })}</h1>
      {scanId && <ScanDetailContent scanId={scanId} />}
    </div>
  )
}
