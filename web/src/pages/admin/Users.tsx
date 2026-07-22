import { useMemo, useState } from 'react'
import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { ConfirmModal } from '../../components/Modal'
import { useToast } from '../../components/Toast'
import { useI18n } from '../../i18n/I18nContext'
import type { LocalAccount } from '../../api/types'

// gateway/auth/rbac.py's KNOWN_ROLES - no frontend endpoint exposes this
// constant, so it's mirrored here (same "small closed enum, safe to
// duplicate" call as elsewhere in this frontend - the backend is always the
// authoritative validator, this only drives the <select> options).
const ROLES = ['submitter', 'approver', 'admin', 'auditor']

const EMPTY_ACCOUNT_FORM = { username: '', role: ROLES[0], initial_password: '' }
const EMPTY_MAPPING_FORM = { group_name: '', role: ROLES[0] }

export function AdminUsersPage() {
  const { t } = useI18n()
  const toast = useToast()

  const {
    data: accountsData,
    loading: accountsLoading,
    error: accountsError,
    reload: reloadAccounts,
  } = useApiData<{ accounts: LocalAccount[] }>(() => api.get('/v1/admin/accounts'), [])
  const {
    data: mappingData,
    loading: mappingLoading,
    error: mappingError,
    reload: reloadMapping,
  } = useApiData<{ group_role_map: Record<string, string> }>(() => api.get('/v1/admin/users'), [])

  const accounts = useMemo(() => accountsData?.accounts ?? [], [accountsData])
  const mappings = useMemo(
    () =>
      Object.entries(mappingData?.group_role_map ?? {})
        .map(([group_name, role]) => ({ group_name, role }))
        .sort((a, b) => a.group_name.localeCompare(b.group_name)),
    [mappingData],
  )

  const [accountForm, setAccountForm] = useState(EMPTY_ACCOUNT_FORM)
  const [creatingAccount, setCreatingAccount] = useState(false)
  const [mappingForm, setMappingForm] = useState(EMPTY_MAPPING_FORM)
  const [savingMapping, setSavingMapping] = useState(false)
  const [pendingDeleteGroup, setPendingDeleteGroup] = useState<string | null>(null)
  const [deletingMapping, setDeletingMapping] = useState(false)
  const [resetTarget, setResetTarget] = useState<LocalAccount | null>(null)
  const [resetPasswordValue, setResetPasswordValue] = useState('')
  const [resetting, setResetting] = useState(false)

  function roleLabel(role: string): string {
    const key = `role.${role}`
    const translated = t(key)
    return translated === key ? role : translated
  }

  async function createAccount(event: React.FormEvent) {
    event.preventDefault()
    setCreatingAccount(true)
    try {
      await api.post('/v1/admin/accounts', accountForm)
      setAccountForm(EMPTY_ACCOUNT_FORM)
      reloadAccounts()
      toast.success(t('adminUsers.accountCreated'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminUsers.accountCreateFailed'))
    } finally {
      setCreatingAccount(false)
    }
  }

  async function updateAccount(account: LocalAccount, patch: { role?: string; status?: string }) {
    try {
      await api.patch(`/v1/admin/accounts/${account.id}`, patch)
      reloadAccounts()
      toast.success(t('adminUsers.accountUpdated'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminUsers.accountUpdateFailed'))
    }
  }

  async function confirmResetPassword() {
    if (!resetTarget) return
    setResetting(true)
    try {
      await api.post(`/v1/admin/accounts/${resetTarget.id}/reset-password`, {
        new_password: resetPasswordValue,
      })
      toast.success(t('adminUsers.passwordResetSucceeded'))
      setResetTarget(null)
      setResetPasswordValue('')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminUsers.passwordResetFailed'))
    } finally {
      setResetting(false)
    }
  }

  async function saveMapping(event: React.FormEvent) {
    event.preventDefault()
    setSavingMapping(true)
    try {
      await api.put(
        `/v1/admin/rbac/group-role-map/${encodeURIComponent(mappingForm.group_name)}`,
        { role: mappingForm.role },
      )
      setMappingForm(EMPTY_MAPPING_FORM)
      reloadMapping()
      toast.success(t('adminUsers.mappingSaved'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminUsers.mappingSaveFailed'))
    } finally {
      setSavingMapping(false)
    }
  }

  async function updateMappingRole(group: string, role: string) {
    try {
      await api.put(`/v1/admin/rbac/group-role-map/${encodeURIComponent(group)}`, { role })
      reloadMapping()
      toast.success(t('adminUsers.mappingSaved'))
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminUsers.mappingSaveFailed'))
    }
  }

  async function confirmDeleteMapping() {
    if (!pendingDeleteGroup) return
    setDeletingMapping(true)
    try {
      await api.delete(`/v1/admin/rbac/group-role-map/${encodeURIComponent(pendingDeleteGroup)}`)
      reloadMapping()
      toast.success(t('adminUsers.mappingDeleted'))
      setPendingDeleteGroup(null)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('adminUsers.mappingDeleteFailed'))
    } finally {
      setDeletingMapping(false)
    }
  }

  return (
    <div>
      <h1>{t('adminUsers.title')}</h1>
      <p className="hint">{t('adminUsers.description')}</p>

      <h2>{t('adminUsers.accountsHeading')}</h2>
      <p className="hint">{t('adminUsers.accountsExplanation')}</p>
      <form className="inline-form" onSubmit={createAccount}>
        <label>
          {t('adminUsers.colUsername')}
          <input
            value={accountForm.username}
            onChange={(e) => setAccountForm({ ...accountForm, username: e.target.value })}
            required
          />
        </label>
        <label>
          {t('adminUsers.colRole')}
          <select
            value={accountForm.role}
            onChange={(e) => setAccountForm({ ...accountForm, role: e.target.value })}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {roleLabel(r)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t('adminUsers.initialPassword')}
          <input
            type="password"
            value={accountForm.initial_password}
            onChange={(e) => setAccountForm({ ...accountForm, initial_password: e.target.value })}
            minLength={12}
            required
          />
        </label>
        <button type="submit" className="primary" disabled={creatingAccount}>
          {creatingAccount ? t('adminUsers.creating') : t('adminUsers.createAccount')}
        </button>
      </form>
      <DataState loading={accountsLoading} error={accountsError} empty={accounts.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('adminUsers.colUsername')}</th>
              <th>{t('adminUsers.colRole')}</th>
              <th>{t('adminUsers.colStatus')}</th>
              <th>{t('adminUsers.colCreatedBy')}</th>
              <th>{t('common.action')}</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.id}>
                <td>{a.username}</td>
                <td>
                  <select value={a.role} onChange={(e) => updateAccount(a, { role: e.target.value })}>
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {roleLabel(r)}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <select
                    value={a.status}
                    onChange={(e) => updateAccount(a, { status: e.target.value })}
                  >
                    <option value="active">{t('adminUsers.statusActive')}</option>
                    <option value="disabled">{t('adminUsers.statusDisabled')}</option>
                  </select>
                </td>
                <td>{a.created_by}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => {
                      setResetTarget(a)
                      setResetPasswordValue('')
                    }}
                  >
                    {t('adminUsers.resetPassword')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>

      <h2 style={{ marginTop: '2rem' }}>{t('adminUsers.mappingHeading')}</h2>
      <p className="hint">{t('adminUsers.mappingExplanation')}</p>
      <form className="inline-form" onSubmit={saveMapping}>
        <label>
          {t('adminUsers.colGroup')}
          <input
            value={mappingForm.group_name}
            onChange={(e) => setMappingForm({ ...mappingForm, group_name: e.target.value })}
            required
          />
        </label>
        <label>
          {t('adminUsers.colRole')}
          <select
            value={mappingForm.role}
            onChange={(e) => setMappingForm({ ...mappingForm, role: e.target.value })}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {roleLabel(r)}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="primary" disabled={savingMapping}>
          {savingMapping ? t('adminUsers.saving') : t('adminUsers.addMapping')}
        </button>
      </form>
      <DataState loading={mappingLoading} error={mappingError} empty={mappings.length === 0}>
        <table>
          <thead>
            <tr>
              <th>{t('adminUsers.colGroup')}</th>
              <th>{t('adminUsers.colRole')}</th>
              <th>{t('common.action')}</th>
            </tr>
          </thead>
          <tbody>
            {mappings.map((m) => (
              <tr key={m.group_name}>
                <td>
                  <code>{m.group_name}</code>
                </td>
                <td>
                  <select
                    value={m.role}
                    onChange={(e) => updateMappingRole(m.group_name, e.target.value)}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {roleLabel(r)}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <button className="danger" onClick={() => setPendingDeleteGroup(m.group_name)}>
                    {t('common.delete')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>

      <ConfirmModal
        open={resetTarget !== null}
        title={t('adminUsers.resetPasswordTitle')}
        description={
          <div>
            <p>
              {resetTarget &&
                t('adminUsers.resetPasswordDescription', { username: resetTarget.username })}
            </p>
            <input
              type="password"
              autoFocus
              value={resetPasswordValue}
              onChange={(e) => setResetPasswordValue(e.target.value)}
              minLength={12}
              placeholder={t('adminUsers.newPasswordPlaceholder')}
            />
          </div>
        }
        confirmLabel={t('adminUsers.resetPassword')}
        busy={resetting}
        onConfirm={confirmResetPassword}
        onCancel={() => {
          setResetTarget(null)
          setResetPasswordValue('')
        }}
      />

      <ConfirmModal
        open={pendingDeleteGroup !== null}
        title={t('adminUsers.confirmDeleteMappingTitle')}
        description={
          pendingDeleteGroup
            ? t('adminUsers.confirmDeleteMappingDescription', { group: pendingDeleteGroup })
            : undefined
        }
        danger
        busy={deletingMapping}
        onConfirm={confirmDeleteMapping}
        onCancel={() => setPendingDeleteGroup(null)}
      />
    </div>
  )
}
