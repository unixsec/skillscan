import { useState } from 'react'
import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { FileField } from '../../components/FileField'
import { useI18n } from '../../i18n/I18nContext'
import { useToast } from '../../components/Toast'
import type { IntelSourceSummary } from '../../api/types'

export function AdminIntelPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, reload } = useApiData<{ sources: IntelSourceSummary[] }>(
    () => api.get('/v1/admin/intel'),
    [],
  )
  const [file, setFile] = useState<File | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleImport(event: React.FormEvent) {
    event.preventDefault()
    if (!file) {
      toast.error(t('adminIntel.noFileError'))
      return
    }
    setSubmitting(true)
    try {
      const form = new FormData()
      form.append('package', file)
      const result = await api.postForm<{ indicators_applied: number }>(
        '/v1/admin/intel/import',
        form,
      )
      setFile(null)
      reload()
      toast.success(t('adminIntel.applied', { count: result.indicators_applied }))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminIntel.importFailed'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <h1>{t('adminIntel.title')}</h1>
      <p className="hint">{t('adminIntel.description')}</p>
      <form className="inline-form" onSubmit={handleImport}>
        <FileField
          label={t('adminIntel.packageLabel')}
          accept=".json"
          file={file}
          onSelect={setFile}
        />
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? t('adminIntel.importing') : t('adminIntel.import')}
        </button>
      </form>
      <DataState loading={loading} error={error} empty={data?.sources.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('adminIntel.colSource')}</th>
              <th>{t('adminIntel.colIndicators')}</th>
              <th>{t('adminIntel.colLastImported')}</th>
            </tr>
          </thead>
          <tbody>
            {data?.sources.map((s) => (
              <tr key={s.source}>
                <td>{s.source}</td>
                <td>{s.indicator_count}</td>
                <td>{s.last_imported_at ? new Date(s.last_imported_at).toLocaleString() : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
    </div>
  )
}
