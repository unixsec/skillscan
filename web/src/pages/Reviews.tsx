import { useCallback, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { ConfirmModal } from '../components/Modal'
import { useToast } from '../components/Toast'
import { useI18n } from '../i18n/I18nContext'
// gate.py's reason codes are rendered by the SHARED translator - the scan
// detail page shows the same codes and must read identically.
import { reasonLabel } from '../i18n/reasons'
import { submitterNames } from '../api/types'
import type { ReviewScan } from '../api/types'

interface PendingDecision {
  scanId: string
  decision: 'approve' | 'reject'
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
              {s.superseded ? (
                <span className="badge badge-neutral">{t('reviews.supersededBadge')}</span>
              ) : (
                <span className="badge badge-review">{t('reviews.pendingBadge')}</span>
              )}
            </div>
            <div className="entity-card-meta">
              {/* The approver's only route from a reason code to the evidence
                  behind it. This page used to render the scan id as truncated
                  TEXT, so a decision to publish or block a skill was made from
                  the automated reasons alone - the findings, hard-gate hits and
                  score were one page away with no way to get there.

                  New tab on purpose: every decision reason typed into the other
                  cards on this page lives in local component state, so an
                  in-place navigation to the scan would silently discard them. */}
              <Link
                to={`/scans/${s.scan_id}`}
                target="_blank"
                rel="noopener noreferrer"
                title={s.scan_id}
              >
                {t('reviews.viewEvidence', { scanId: s.scan_id.slice(0, 8) })}
              </Link>
              {' · '}
              {/* 里程碑 F Task 16: every rightful submitter, not just the first.
                  Byte-identical submissions collapse onto one scan_job, so on a
                  deduplicated scan the first submitter's name is a stranger's to
                  everyone who submitted afterwards - and this queue showed only
                  that one name.

                  It matters more here than on the scan list because SoD forbids
                  approving a scan you submitted. 608f299 (2026-07-29, milestone
                  F Task 18) closed the gap where that check only compared
                  against `job.submitter`, the FIRST submitter: gate/reviews.py's
                  submit_review_decision now ALSO checks membership in
                  scan_submitter (is_scan_submitter), so a co-submitter is
                  refused too, not just the one name the scalar column
                  remembers. Showing every name here still matters - it is how
                  an approver visually confirms who is actually barred - but it
                  is no longer standing in for a backend gap; the backend
                  enforces this itself. */}
              {t('reviews.metaLine', {
                submitter: submitterNames(s).join(', ') || t('reviews.unknownSubmitter'),
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
            {/* I3: a superseded entry is SHOWN, not hidden - an item that
                silently vanishes teaches an approver nothing - but it offers
                no decision, because the backend refuses one (409) and the
                lifecycle worker would discard it anyway. The explanation is
                the actual product here: the sign-off used to be accepted,
                signed, and then thrown away with no feedback at all. */}
            {s.superseded ? (
              <p className="hint">{t('reviews.supersededHint')}</p>
            ) : (
              <>
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
              </>
            )}
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
