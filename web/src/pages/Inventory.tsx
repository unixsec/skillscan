import { useCallback, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { Drawer } from '../components/Drawer'
import { ConfirmModal } from '../components/Modal'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useToast } from '../components/Toast'
import { useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'
import type { InventoryDetail, InventorySkill } from '../api/types'

function lifecycleLabel(t: (k: string) => string, state: string): string {
  const key = `lifecycle.${state}`
  const translated = t(key)
  return translated === key ? state : translated
}

function trustTierLabel(t: (k: string) => string, tier: string): string {
  const key = `trustTier.${tier}`
  const translated = t(key)
  return translated === key ? tier : translated
}

export function InventoryListPage() {
  const { t } = useI18n()
  const [searchParams, setSearchParams] = useSearchParams()
  const detailSkillId = searchParams.get('detail')
  const { data, loading, error } = useApiData<{ skills: InventorySkill[] }>(
    () => api.get('/v1/inventory'),
    [],
  )
  const skills = useMemo(() => data?.skills ?? [], [data])
  const filterFields: FilterField<InventorySkill>[] = useMemo(
    () => [
      {
        key: 'state',
        label: t('inventory.colState'),
        value: (row) => row.state ?? '',
        renderOption: (v) => lifecycleLabel(t, v),
      },
      {
        key: 'trust_tier',
        label: t('inventory.colTrustTier'),
        value: (row) => row.trust_tier,
        renderOption: (v) => {
          const key = `trustTier.${v}`
          const translated = t(key)
          return translated === key ? v : translated
        },
      },
      { key: 'source', label: t('inventory.colSource'), value: (row) => row.source },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(skills, filterFields)

  function openDetail(e: React.MouseEvent, skillId: string) {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('detail', skillId)
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

  return (
    <div>
      <h1>{t('inventory.title')}</h1>
      <DataState loading={loading} error={error} empty={skills.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        <table>
          <thead>
            <tr>
              <th>{t('inventory.colSkillId')}</th>
              <th>{t('inventory.colSource')}</th>
              <th>{t('inventory.colTrustTier')}</th>
              <th>{t('inventory.colState')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.skill_id}>
                <td>
                  <Link to={`/inventory/${s.skill_id}`} onClick={(e) => openDetail(e, s.skill_id)}>
                    {s.skill_id}
                  </Link>
                </td>
                <td>{s.source}</td>
                <td>{trustTierLabel(t, s.trust_tier)}</td>
                <td>{s.state ? lifecycleLabel(t, s.state) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
      <Drawer
        open={detailSkillId !== null}
        title={detailSkillId ? t('inventory.detailTitle', { skillId: detailSkillId }) : ''}
        onClose={closeDrawer}
      >
        {detailSkillId && <InventoryDetailContent skillId={detailSkillId} />}
      </Drawer>
    </div>
  )
}

export function InventoryDetailContent({ skillId }: { skillId: string }) {
  const { session } = useSession()
  const { t } = useI18n()
  const toast = useToast()
  const isAdmin = session?.roles.includes('admin') ?? false
  const { data, loading, error, reload } = useApiData<InventoryDetail>(
    () => api.get(`/v1/inventory/${skillId}`),
    [skillId],
  )
  const [reason, setReason] = useState('')
  const [pendingAction, setPendingAction] = useState<'quarantine' | 'retire' | null>(null)
  const [busy, setBusy] = useState(false)

  async function confirmTransition() {
    if (!pendingAction) return
    setBusy(true)
    try {
      await api.post(`/v1/inventory/${skillId}/${pendingAction}`, { reason })
      reload()
      toast.success(
        pendingAction === 'quarantine' ? t('inventory.quarantineSucceeded') : t('inventory.retireSucceeded'),
      )
      setPendingAction(null)
    } catch (err) {
      const fallback =
        pendingAction === 'quarantine' ? t('inventory.quarantineFailed') : t('inventory.retireFailed')
      toast.error(err instanceof ApiError ? err.detail : fallback)
    } finally {
      setBusy(false)
    }
  }

  // Memoized so its identity is stable across re-renders while the modal is
  // open/busy - ConfirmModal's focus-management effect is keyed on
  // [open, onCancel], and a new closure here every render would tear
  // down/re-run that effect on every re-render, causing a focus flicker.
  const cancelAction = useCallback(() => setPendingAction(null), [])

  return (
    <DataState loading={loading} error={error}>
      {data && (
        <>
          <div className="summary-grid">
            <div className="summary-stat">
              <div className="value">{data.state ?? '—'}</div>
              <div className="label">{t('inventory.statState')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">{trustTierLabel(t, data.trust_tier)}</div>
              <div className="label">{t('inventory.statTrustTier')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">{data.versions.length}</div>
              <div className="label">{t('inventory.statVersions')}</div>
            </div>
          </div>
          {isAdmin && (
            <div className="card">
              <label>
                {t('common.reason')}
                <input value={reason} onChange={(e) => setReason(e.target.value)} />
              </label>{' '}
              <button className="danger" onClick={() => setPendingAction('quarantine')}>
                {t('inventory.quarantine')}
              </button>{' '}
              <button className="danger" onClick={() => setPendingAction('retire')}>
                {t('inventory.retire')}
              </button>
            </div>
          )}
          <h2>{t('inventory.versionsHeading')}</h2>
          <table>
            <thead>
              <tr>
                <th>{t('inventory.colContentHash')}</th>
                <th>{t('inventory.colToolchainDigest')}</th>
                <th>{t('inventory.colCreated')}</th>
              </tr>
            </thead>
            <tbody>
              {data.versions.map((v) => (
                <tr key={v.content_hash}>
                  <td>
                    <code>{v.content_hash.slice(0, 16)}…</code>
                  </td>
                  <td>
                    <code>{v.toolchain_digest.slice(0, 16)}…</code>
                  </td>
                  <td>{new Date(v.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.baseline && (
            <p className="hint">
              {t('inventory.baseline', {
                hash: `${data.baseline.content_hash.slice(0, 16)}…`,
                when: new Date(data.baseline.approved_at).toLocaleString(),
              })}
            </p>
          )}
          <ConfirmModal
            open={pendingAction !== null}
            title={
              pendingAction === 'quarantine'
                ? t('inventory.confirmQuarantineTitle')
                : t('inventory.confirmRetireTitle')
            }
            description={t('inventory.confirmDescription', { skillId })}
            danger
            busy={busy}
            onConfirm={confirmTransition}
            onCancel={cancelAction}
          />
        </>
      )}
    </DataState>
  )
}

export function InventoryDetailPage() {
  const { skillId } = useParams<{ skillId: string }>()
  const { t } = useI18n()
  return (
    <div>
      <h1>{t('inventory.detailTitle', { skillId: skillId ?? '' })}</h1>
      {skillId && <InventoryDetailContent skillId={skillId} />}
    </div>
  )
}
