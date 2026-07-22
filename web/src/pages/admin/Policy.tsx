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
function policyTemplate(active: ActivePolicy): string {
  const engines = active.required_engines.map((e) => `  - ${e}`).join('\n')
  const hardGates = active.hard_gate_rules.length
    ? active.hard_gate_rules.map((r) => `  - ${r}`).join('\n')
    : '  # - pii.us_ssn'
  return `# 新策略版本号 - 必须与当前生效版本不同
version: "${active.version}-draft"

# 必须始终跑完的引擎（INV-1：这些引擎缺失则本次扫描 required_ok=false）
# 从当前生效策略预填，如需增删请谨慎
required_engines:
${engines}

# 不可加白豁免的规则 ID（INV-3/INV-8：无论 allowlist scope 如何都强制拦截）
# 留空表示没有强制硬门规则
hard_gate_rules:
${hardGates}

# 复核阈值：置信度低于此值的发现不计入判定（0-1 之间）
review_confidence: ${active.review_confidence}

# 达到此严重级别 -> 直接 BLOCK
block_on_severity: ${active.block_on_severity}

# 达到此严重级别 -> 转人工复核（REVIEW）
review_on_severity: ${active.review_on_severity}

# 按信任级别收紧（只能收紧，不能放宽）block 阈值，可选，删除整段等于不覆盖
# tier_block_overrides:
#   - tier: public
#     severity: HIGH

# 加白列表能豁免的最高严重级别，超过此级别不可加白
allowlistable_max_severity: HIGH

# 策略引擎自身出错时的兜底判定（永远选保守项，即 BLOCK）
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
                  onClick={() => setYaml(policyTemplate(data.active_policy))}
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
