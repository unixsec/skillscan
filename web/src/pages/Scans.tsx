import { useCallback, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { Drawer } from '../components/Drawer'
import { FileField } from '../components/FileField'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useToast } from '../components/Toast'
import { VerdictBadge } from '../components/Badge'
import { useI18n } from '../i18n/I18nContext'
import type { ScanSummary } from '../api/types'
import { ScanDetailContent } from './ScanDetail'

export function ScansPage() {
  const { t } = useI18n()
  const toast = useToast()
  const [searchParams, setSearchParams] = useSearchParams()
  const detailScanId = searchParams.get('detail')
  const { data, loading, error, reload } = useApiData<{ items: ScanSummary[] }>(
    () => api.get('/v1/scans'),
    [],
  )
  const [file, setFile] = useState<File | null>(null)
  const [skillId, setSkillId] = useState('')
  const [trustTier, setTrustTier] = useState('internal')
  const [submitting, setSubmitting] = useState(false)

  const items = useMemo(() => data?.items ?? [], [data])
  const filterFields: FilterField<ScanSummary>[] = useMemo(
    () => [
      {
        key: 'state',
        label: t('scans.colState'),
        value: (row) => row.state,
        renderOption: (v) => {
          const key = `scanState.${v}`
          const translated = t(key)
          return translated === key ? v : translated
        },
      },
      { key: 'submitter', label: t('scans.colSubmitter'), value: (row) => row.submitter },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(items, filterFields)

  function openDetail(e: React.MouseEvent, scanId: string) {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('detail', scanId)
      return next
    })
  }

  // Memoized so its identity is stable across re-renders while the drawer is
  // open - Drawer's focus-management effect is keyed on [open, onClose], and
  // a new closure here every render would tear down/re-run that effect on
  // every re-render, causing a focus flicker.
  const closeDrawer = useCallback(() => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.delete('detail')
      return next
    })
  }, [setSearchParams])

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    if (!file) {
      toast.error(t('scans.noFileError'))
      return
    }
    setSubmitting(true)
    try {
      const form = new FormData()
      form.append('package', file)
      // Optional inventory registration: naming a skill_id makes this
      // submission enter the lifecycle state machine (visible on Inventory).
      if (skillId.trim()) {
        form.append('skill_id', skillId.trim())
        form.append('trust_tier', trustTier)
      }
      await api.postForm('/v1/scans', form)
      setFile(null)
      setSkillId('')
      reload()
      toast.success(t('scans.submitSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('scans.submitFailed'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <h1>{t('scans.title')}</h1>
      <form className="inline-form" onSubmit={handleSubmit}>
        <FileField label={t('scans.packageLabel')} file={file} onSelect={setFile} />
        <label>
          {t('scans.skillIdLabel')}
          <input
            value={skillId}
            onChange={(e) => setSkillId(e.target.value)}
            placeholder={t('scans.skillIdPlaceholder')}
          />
        </label>
        {skillId.trim() && (
          <label>
            {t('scans.trustTierLabel')}
            <select value={trustTier} onChange={(e) => setTrustTier(e.target.value)}>
              <option value="internal">{t('trustTier.internal')}</option>
              <option value="partner">{t('trustTier.partner')}</option>
              <option value="public">{t('trustTier.public')}</option>
            </select>
          </label>
        )}
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? t('scans.submitting') : t('scans.submit')}
        </button>
      </form>
      <DataState loading={loading} error={error} empty={items.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        <table>
          <thead>
            <tr>
              <th>{t('scans.colScanId')}</th>
              <th>{t('scans.colSkillName')}</th>
              <th>{t('scans.colSkillId')}</th>
              <th>{t('scans.colState')}</th>
              <th>{t('scans.colVerdict')}</th>
              <th>{t('scans.colSubmitter')}</th>
              <th>{t('scans.colContentHash')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.scan_id}>
                <td>
                  <Link to={`/scans/${s.scan_id}`} onClick={(e) => openDetail(e, s.scan_id)}>
                    {s.scan_id.slice(0, 8)}…
                  </Link>
                </td>
                <td>{s.skill_name ?? <span className="hint">{t('scans.noSkillName')}</span>}</td>
                <td>{s.skill_id ?? <span className="hint">{t('scans.noSkillId')}</span>}</td>
                <td>{t(`scanState.${s.state}`) === `scanState.${s.state}` ? s.state : t(`scanState.${s.state}`)}</td>
                <td>
                  <VerdictBadge verdict={s.verdict} />
                </td>
                <td>{s.submitter}</td>
                <td>
                  <code>{s.content_hash.slice(0, 12)}…</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
      <Drawer
        open={detailScanId !== null}
        title={detailScanId ? t('scanDetail.title', { scanId: detailScanId }) : ''}
        onClose={closeDrawer}
      >
        {detailScanId && <ScanDetailContent scanId={detailScanId} />}
      </Drawer>
    </div>
  )
}
