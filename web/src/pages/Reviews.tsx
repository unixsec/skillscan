import { useCallback, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { ConfirmModal } from '../components/Modal'
import { useToast } from '../components/Toast'
import { useI18n } from '../i18n/I18nContext'
import type { ReviewScan } from '../api/types'

interface PendingDecision {
  scanId: string
  decision: 'approve' | 'reject'
}

// Translates gate.decide()'s machine-oriented reason codes (skillscan_core/
// gate.py) into a human sentence - "依据" (item #5's second ask). Every shape
// that function can actually emit is matched explicitly; anything else falls
// through to reasonUnknown, which still shows the raw code rather than
// hiding it - an unrecognized code is a sign this list drifted out of sync
// with gate.py, not something to silently swallow.
function reasonLabel(t: (k: string, params?: Record<string, string>) => string, code: string): string {
  const severityLabel = (level: string): string => {
    const key = `severity.${level.toLowerCase()}`
    const translated = t(key)
    return translated === key ? level : translated
  }
  if (code.startsWith('severity_all=')) {
    return t('reviews.reasonSeverityAll', { level: severityLabel(code.slice('severity_all='.length)) })
  }
  if (code.startsWith('severity_non_llm=')) {
    return t('reviews.reasonSeverityNonLlm', { level: severityLabel(code.slice('severity_non_llm='.length)) })
  }
  if (code.startsWith('hard_gate_hit:')) {
    return t('reviews.reasonHardGateHit', { rules: code.slice('hard_gate_hit:'.length) })
  }
  if (code.startsWith('fail_closed:required_engine_missing_or_failed:')) {
    return t('reviews.reasonFailClosed', {
      detail: code.slice('fail_closed:required_engine_missing_or_failed:'.length),
    })
  }
  if (code === 'dedup_collision_signal_restored_from_scan_result') {
    return t('reviews.reasonDedupCollision')
  }
  if (code === 'findings_capped_forces_review') {
    return t('reviews.reasonFindingsCapped')
  }
  return t('reviews.reasonUnknown', { code })
}

export function ReviewsPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, reload } = useApiData<{ scans: ReviewScan[] }>(
    () => api.get('/v1/reviews'),
    [],
  )
  const [reason, setReason] = useState<Record<string, string>>({})
  const [pending, setPending] = useState<PendingDecision | null>(null)
  const [busy, setBusy] = useState(false)

  async function confirmDecision() {
    if (!pending) return
    setBusy(true)
    try {
      await api.post(`/v1/reviews/${pending.scanId}`, {
        decision: pending.decision,
        reason: reason[pending.scanId] ?? '',
      })
      reload()
      toast.success(pending.decision === 'approve' ? t('reviews.approveSucceeded') : t('reviews.rejectSucceeded'))
      setPending(null)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('reviews.decisionFailed'))
    } finally {
      setBusy(false)
    }
  }

  const cancelPending = useCallback(() => setPending(null), [])

  return (
    <div>
      <h1>{t('reviews.title')}</h1>
      <p className="hint">{t('reviews.description')}</p>
      <DataState loading={loading} error={error} empty={data?.scans.length === 0}>
        {data?.scans.map((s) => (
          <div className="entity-card" key={s.scan_id}>
            <div className="entity-card-top">
              <span className="entity-card-name">
                {s.skill_id ?? <span className="hint">{t('scans.noSkillId')}</span>}
              </span>
              <span className="badge badge-review">{t('reviews.pendingBadge')}</span>
            </div>
            <div className="entity-card-meta">
              {t('reviews.metaLine', {
                scanId: s.scan_id.slice(0, 8),
                submitter: s.submitter ?? t('reviews.unknownSubmitter'),
                issuedAt: new Date(s.issued_at).toLocaleString(),
              })}
            </div>
            <div className="hint" style={{ marginTop: '0.5rem', marginBottom: '0.25rem' }}>
              {t('reviews.autoReasonsHeading')}
            </div>
            {s.reasons.length === 0 ? (
              <p className="hint">—</p>
            ) : (
              <ul style={{ margin: '0 0 0.75rem', paddingLeft: '1.25rem' }}>
                {s.reasons.map((code) => (
                  <li key={code}>{reasonLabel(t, code)}</li>
                ))}
              </ul>
            )}
            <label>
              {t('reviews.colDecisionReason')}
              <input
                type="text"
                value={reason[s.scan_id] ?? ''}
                onChange={(e) => setReason({ ...reason, [s.scan_id]: e.target.value })}
                placeholder={t('reviews.reasonPlaceholder')}
              />
            </label>
            <div style={{ marginTop: '0.5rem' }}>
              <button className="primary" onClick={() => setPending({ scanId: s.scan_id, decision: 'approve' })}>
                {t('reviews.approve')}
              </button>{' '}
              <button className="danger" onClick={() => setPending({ scanId: s.scan_id, decision: 'reject' })}>
                {t('reviews.reject')}
              </button>
            </div>
          </div>
        ))}
      </DataState>
      <ConfirmModal
        open={pending !== null}
        title={pending?.decision === 'approve' ? t('reviews.confirmApproveTitle') : t('reviews.confirmRejectTitle')}
        description={
          pending
            ? t('reviews.confirmDescription', {
                scanId: pending.scanId.slice(0, 8),
                reason: reason[pending.scanId] || t('reviews.noReason'),
              })
            : undefined
        }
        danger={pending?.decision === 'reject'}
        busy={busy}
        onConfirm={confirmDecision}
        onCancel={cancelPending}
      />
    </div>
  )
}
