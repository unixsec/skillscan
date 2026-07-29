import { useState } from 'react'
import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { useI18n } from '../../i18n/I18nContext'
import { useToast } from '../../components/Toast'
import type { ActivePolicy, PolicyStatus } from '../../api/types'

// Mirrors policies/gate/v1.yaml's real field set exactly (the backend parses
// proposals with the same yaml.safe_load, gate/policy_workflow.py) - a field
// name here that doesn't match that file would silently be ignored or
// rejected by the real parser, so this is generated from the SAME shape, not
// a hand-drifted approximation. Pre-fills required_engines/hard_gate_rules
// from the currently active policy so a proposal starts from real values,
// not a generic example; the four fields the summary API doesn't expose
// (tier_block_overrides etc.) get documented, sensible starting defaults.
//
// The explanatory comment lines come from `t()` (adminPolicy.template.*) so
// an English-locale admin edits an English-commented form instead of a
// Chinese one regardless of what language they picked - only the YAML field
// names/values, which the real parser cares about, stay literal.
function policyTemplate(active: ActivePolicy, t: (key: string) => string): string {
  const engines = active.required_engines.map((e) => `  - ${e}`).join('\n')
  const hardGates = active.hard_gate_rules.length
    ? active.hard_gate_rules.map((r) => `  - ${r}`).join('\n')
    : '  # - pii.us_ssn'
  return `${t('adminPolicy.template.version')}
version: "${active.version}-draft"

${t('adminPolicy.template.requiredEnginesComment1')}
${t('adminPolicy.template.requiredEnginesComment2')}
required_engines:
${engines}

${t('adminPolicy.template.hardGateRulesComment1')}
${t('adminPolicy.template.hardGateRulesComment2')}
hard_gate_rules:
${hardGates}

${t('adminPolicy.template.reviewConfidence')}
review_confidence: ${active.review_confidence}

${t('adminPolicy.template.blockOnSeverity')}
block_on_severity: ${active.block_on_severity}

${t('adminPolicy.template.reviewOnSeverity')}
review_on_severity: ${active.review_on_severity}

${t('adminPolicy.template.tierBlockOverridesIntro')}
${t('adminPolicy.template.tierBlockOverridesExample')}

${t('adminPolicy.template.allowlistableMaxSeverity')}
allowlistable_max_severity: HIGH

${t('adminPolicy.template.failClosedVerdict')}
fail_closed_verdict: BLOCK
`
}

export function AdminPolicyPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { data, loading, error, reload } = useApiData<PolicyStatus>(
    () => api.get('/v1/admin/policy'),
    [],
  )
  const [yaml, setYaml] = useState('')

  async function propose(event: React.FormEvent) {
    event.preventDefault()
    try {
      await api.post('/v1/admin/policy', { policy_yaml: yaml })
      setYaml('')
      reload()
      toast.success(t('adminPolicy.proposeSucceeded'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminPolicy.proposeFailed'))
    }
  }

  async function decide(id: number, action: 'approve' | 'reject') {
    try {
      await api.post(`/v1/admin/policy/${id}/${action}`, {})
      reload()
      toast.success(action === 'approve' ? t('adminPolicy.approveSucceeded') : t('adminPolicy.rejectSucceeded'))
    } catch (err) {
      const fallback =
        action === 'approve' ? t('adminPolicy.approveFailed') : t('adminPolicy.rejectFailed')
      toast.error(err instanceof ApiError ? err.detail : fallback)
    }
  }

  return (
    <div>
      <h1>{t('adminPolicy.title')}</h1>
      <DataState loading={loading} error={error}>
        {data && (
          <>
            <div className="card">
              <h2 style={{ marginTop: 0 }}>
                {t('adminPolicy.activePolicy', { version: data.active_policy.version })}
              </h2>
              <p className="hint">
                {t('adminPolicy.requiredEngines', {
                  engines: data.active_policy.required_engines.join(', '),
                })}
              </p>
              <p className="hint">
                {t('adminPolicy.hardGateRules', {
                  rules: data.active_policy.hard_gate_rules.join(', ') || t('adminPolicy.none'),
                })}
              </p>
            </div>

            <h2>{t('adminPolicy.propose')}</h2>
            <p className="hint">{t('adminPolicy.proposeGuide')}</p>
            <form onSubmit={propose} style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div>
                <button
                  type="button"
                  onClick={() => setYaml(policyTemplate(data.active_policy, t))}
                  style={{ width: 'fit-content' }}
                >
                  {t('adminPolicy.insertTemplate')}
                </button>
              </div>
              <textarea
                rows={20}
                value={yaml}
                onChange={(e) => setYaml(e.target.value)}
                placeholder={t('adminPolicy.proposePlaceholder')}
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
              />
              <button type="submit" className="primary" style={{ width: 'fit-content' }}>
                {t('adminPolicy.submitProposal')}
              </button>
            </form>

            <h2>{t('adminPolicy.pending', { count: data.pending_proposals.length })}</h2>
            {data.pending_proposals.length === 0 ? (
              <p className="hint">{t('adminPolicy.nonePending')}</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>{t('adminPolicy.colId')}</th>
                    <th>{t('adminPolicy.colProposedBy')}</th>
                    <th>{t('adminPolicy.colHardGateChange')}</th>
                    <th>{t('common.action')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.pending_proposals.map((p) => (
                    <tr key={p.id}>
                      <td>{p.id}</td>
                      <td>{p.proposed_by}</td>
                      <td>{p.changes_hard_gate_rules ? t('common.yes') : t('common.no')}</td>
                      <td>
                        <button className="primary" onClick={() => decide(p.id, 'approve')}>
                          {t('adminPolicy.approve')}
                        </button>{' '}
                        <button className="danger" onClick={() => decide(p.id, 'reject')}>
                          {t('adminPolicy.reject')}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </DataState>
    </div>
  )
}
