import { useMemo, useState, useCallback } from 'react'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { ConfirmModal } from '../components/Modal'
import { useToast } from '../components/Toast'
import { useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'
import type { AllowlistCandidates, AllowlistEntry } from '../api/types'

const EMPTY_FORM = {
  scope_type: 'skill_id',
  scope_value: '',
  rule_id: '',
  expires_hours: '24',
  requested_by: '',
  reason: '',
}

// UX (item #8): a content_hash-scoped entry is otherwise a bare hash with no
// indication of which skill it is - resolved_skill_id (populated server-side,
// gate/router.py) is used here whenever available; falls back to the raw
// scope_type: scope_value pairing only when it truly can't be resolved (e.g.
// an anonymous/unregistered scan's content_hash).
function scopeLabel(t: (k: string, params?: Record<string, string>) => string, e: AllowlistEntry): string {
  if (e.scope_type === 'skill_id') {
    return t('allowlist.scopeLabelSkillId', { skillId: e.scope_value })
  }
  if (e.scope_type === 'content_hash') {
    const hashPrefix = `${e.scope_value.slice(0, 12)}…`
    return e.resolved_skill_id
      ? t('allowlist.scopeLabelContentHashResolved', { skillId: e.resolved_skill_id, hash: hashPrefix })
      : t('allowlist.scopeLabelContentHashUnresolved', { hash: hashPrefix })
  }
  return t('allowlist.scopeLabelRuleGlobal')
}

export function AllowlistPage() {
  const { session } = useSession()
  const { t } = useI18n()
  const toast = useToast()
  const isAdmin = session?.roles.includes('admin') ?? false
  const { data, loading, error, reload } = useApiData<{
    entries: AllowlistEntry[]
    candidates: AllowlistCandidates
  }>(() => api.get('/v1/allowlist'), [])
  const [form, setForm] = useState(EMPTY_FORM)
  const [submitting, setSubmitting] = useState(false)
  const [pendingRevoke, setPendingRevoke] = useState<AllowlistEntry | null>(null)
  const [revoking, setRevoking] = useState(false)

  const skills = useMemo(() => data?.candidates.skills ?? [], [data])
  const ruleIds = useMemo(() => data?.candidates.rule_ids ?? [], [data])
  const contentHashOptions = useMemo(
    () => skills.flatMap((s) => s.content_hashes.map((h) => ({ skillId: s.skill_id, hash: h }))),
    [skills],
  )
  const selectedRule = useMemo(
    () => ruleIds.find((r) => r.rule_id === form.rule_id),
    [ruleIds, form.rule_id],
  )

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    try {
      const expiresAt = Date.now() / 1000 + Number(form.expires_hours) * 3600
      await api.post('/v1/allowlist', {
        scope_type: form.scope_type,
        scope_value: form.scope_value,
        rule_id: form.rule_id,
        expires_at: expiresAt,
        requested_by: form.requested_by,
        reason: form.reason,
      })
      setForm(EMPTY_FORM)
      reload()
      toast.success(t('allowlist.grantSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('allowlist.grantFailed'))
    } finally {
      setSubmitting(false)
    }
  }

  async function confirmRevoke() {
    if (!pendingRevoke?.id) return
    setRevoking(true)
    try {
      await api.delete(`/v1/allowlist/${pendingRevoke.id}`)
      reload()
      toast.success(t('allowlist.revokeSucceeded'))
      setPendingRevoke(null)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('allowlist.revokeFailed'))
    } finally {
      setRevoking(false)
    }
  }

  const cancelRevoke = useCallback(() => setPendingRevoke(null), [])

  return (
    <div>
      <h1>{t('allowlist.title')}</h1>
      <p className="hint">{t('allowlist.description')}</p>
      <form className="inline-form" onSubmit={handleSubmit}>
        <label>
          {t('allowlist.scopeType')}
          <select
            value={form.scope_type}
            onChange={(e) => setForm({ ...form, scope_type: e.target.value, scope_value: '' })}
          >
            <option value="skill_id">{t('allowlist.scopeSkillId')}</option>
            <option value="content_hash">{t('allowlist.scopeContentHash')}</option>
            <option value="rule_global">{t('allowlist.scopeRuleGlobal')}</option>
          </select>
        </label>
        {form.scope_type !== 'rule_global' && (
          <label>
            {t('allowlist.scopeValue')}
            <input
              list={form.scope_type === 'skill_id' ? 'allowlist-skill-ids' : 'allowlist-content-hashes'}
              value={form.scope_value}
              onChange={(e) => setForm({ ...form, scope_value: e.target.value })}
              placeholder={
                form.scope_type === 'skill_id'
                  ? t('allowlist.scopeValueSkillIdPlaceholder')
                  : t('allowlist.scopeValueContentHashPlaceholder')
              }
              required
            />
            <datalist id="allowlist-skill-ids">
              {skills.map((s) => (
                <option value={s.skill_id} key={s.skill_id} />
              ))}
            </datalist>
            <datalist id="allowlist-content-hashes">
              {contentHashOptions.map((o) => (
                <option value={o.hash} key={o.hash} label={`${o.skillId} — ${o.hash.slice(0, 12)}…`} />
              ))}
            </datalist>
          </label>
        )}
        <label>
          {t('allowlist.ruleId')}
          <input
            list="allowlist-rule-ids"
            value={form.rule_id}
            onChange={(e) => setForm({ ...form, rule_id: e.target.value })}
            placeholder={t('allowlist.ruleIdPlaceholder')}
            required
          />
          <datalist id="allowlist-rule-ids">
            {ruleIds.map((r) => (
              <option value={r.rule_id} key={r.rule_id} label={r.is_hard_gate ? t('allowlist.hardGateTag') : ''} />
            ))}
          </datalist>
          {selectedRule?.is_hard_gate && (
            <p className="hint">{isAdmin ? t('allowlist.hardGateAdminOk') : t('allowlist.hardGateNeedsAdmin')}</p>
          )}
        </label>
        <label>
          {t('allowlist.expiresHours')}
          <input
            type="number"
            min={1}
            value={form.expires_hours}
            onChange={(e) => setForm({ ...form, expires_hours: e.target.value })}
          />
        </label>
        <label>
          {t('allowlist.requestedBy')}
          <input
            value={form.requested_by}
            onChange={(e) => setForm({ ...form, requested_by: e.target.value })}
            required
          />
        </label>
        <label>
          {t('common.reason')}
          <input value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </label>
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? t('allowlist.granting') : t('allowlist.grant')}
        </button>
      </form>
      <DataState loading={loading} error={error} empty={data?.entries.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('allowlist.colRule')}</th>
              <th>{t('allowlist.colScope')}</th>
              <th>{t('allowlist.colApprovedBy')}</th>
              <th>{t('allowlist.colRequestedBy')}</th>
              <th>{t('allowlist.colExpires')}</th>
              {isAdmin && <th>{t('common.action')}</th>}
            </tr>
          </thead>
          <tbody>
            {data?.entries.map((e) => (
              <tr key={e.id}>
                <td>
                  <code>{e.rule_id}</code>
                </td>
                <td>{scopeLabel(t, e)}</td>
                <td>{e.approved_by}</td>
                <td>{e.requested_by}</td>
                <td>{new Date(e.expires_at).toLocaleString()}</td>
                {isAdmin && (
                  <td>
                    <button className="danger" onClick={() => e.id && setPendingRevoke(e)}>
                      {t('allowlist.revoke')}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
      <ConfirmModal
        open={pendingRevoke !== null}
        title={t('allowlist.confirmRevokeTitle')}
        description={pendingRevoke ? t('allowlist.confirmRevokeDescription', { ruleId: pendingRevoke.rule_id }) : undefined}
        danger
        busy={revoking}
        onConfirm={confirmRevoke}
        onCancel={cancelRevoke}
      />
    </div>
  )
}
