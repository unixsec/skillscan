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

// The lifecycle state answers "may anyone use this skill?", so the states that
// mean NO have to look different from the ones that mean "not yet". Until
// milestone F Task 1 gave BLOCK its own terminal state, a blocked skill sat in
// `scanning` forever and was indistinguishable from one still being scanned -
// the exact confusion this colouring exists to prevent. Unknown states fall
// back to neutral rather than being guessed into a colour.
const LIFECYCLE_BADGE_CLASS: Record<string, string> = {
  submitted: 'badge badge-neutral',
  scanning: 'badge badge-neutral',
  review_pending: 'badge badge-review',
  published: 'badge badge-pass',
  blocked: 'badge badge-block',
  quarantined: 'badge badge-block',
  retired: 'badge badge-neutral',
}

// Exported so any other page rendering an InventorySkill/InventoryDetail/
// UnownedSkill.state (e.g. admin/Ownership.tsx) reuses this instead of
// writing a third "translate a lifecycle state" - see
// lifecycleStateGuard.test.ts, which fails loudly if a raw `.state` value
// gets rendered outside this component again.
export function LifecycleBadge({ state }: { state: string | null }) {
  const { t } = useI18n()
  // No lifecycle row at all (a scan submitted without a skill_id never enters
  // the state machine) - absence, never a guessed state.
  if (!state) return <span className="badge badge-neutral">—</span>
  return (
    <span className={LIFECYCLE_BADGE_CLASS[state] ?? 'badge badge-neutral'}>
      {lifecycleLabel(t, state)}
    </span>
  )
}

// Every lifecycle state whose VALID_TRANSITIONS target set contains
// "retired" - i.e. every state from which clicking Retire is a legal
// transition rather than a guaranteed 409. Derived from (not hand-guessed
// alongside) `apps/monolith/modules/inventory/lifecycle.py`'s
// VALID_TRANSITIONS, the single source of truth for the whole state machine:
//
//   "submitted":      frozenset({"scanning"})                                -> no "retired"
//   "scanning":       frozenset({"published", "review_pending",
//                                 "retired", "blocked"})                     -> has "retired"
//   "review_pending": frozenset({"published", "retired", "submitted"})       -> has "retired"
//   "published":      frozenset({"quarantined", "retired", "submitted"})     -> has "retired"
//   "quarantined":    frozenset({"published", "retired"})                   -> has "retired"
//   "blocked":        frozenset({"scanning", "retired", "submitted"})        -> has "retired"
//   "retired":        frozenset()                                           -> terminal, no "retired"
//
// So only "submitted" (its lone edge is "scanning") and "retired" itself
// (terminal) are excluded. Inventory.test.tsx parses the REAL text of that
// Python file at test time and asserts it produces exactly this set, so a
// change to the backend table that isn't mirrored here fails a test instead
// of shipping a button that 409s - the same class of "new state/edge added,
// derived registry not updated" defect milestone D hit five times.
export const RETIRE_ELIGIBLE_STATES: ReadonlySet<string> = new Set([
  'scanning',
  'review_pending',
  'published',
  'quarantined',
  'blocked',
])

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
                <td>
                  <LifecycleBadge state={s.state} />
                </td>
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
  const [pendingAction, setPendingAction] = useState<'quarantine' | 'restore' | 'retire' | null>(null)
  const [busy, setBusy] = useState(false)
  // 里程碑 F Task 15: assign/transfer `skill.owner`, its own state because it
  // is its own endpoint with its own body - and because it is a PRIVILEGE
  // change rather than a lifecycle move, which is worth keeping visually
  // separate from the quarantine/retire controls next to it.
  const [ownerDraft, setOwnerDraft] = useState('')
  const [ownerReason, setOwnerReason] = useState('')
  const [ownerConfirming, setOwnerConfirming] = useState(false)
  const [ownerBusy, setOwnerBusy] = useState(false)

  const SUCCESS_KEYS = {
    quarantine: 'inventory.quarantineSucceeded',
    restore: 'inventory.restoreSucceeded',
    retire: 'inventory.retireSucceeded',
  } as const
  const FAILURE_KEYS = {
    quarantine: 'inventory.quarantineFailed',
    restore: 'inventory.restoreFailed',
    retire: 'inventory.retireFailed',
  } as const

  async function confirmTransition() {
    if (!pendingAction) return
    setBusy(true)
    try {
      await api.post(`/v1/inventory/${skillId}/${pendingAction}`, { reason })
      reload()
      toast.success(t(SUCCESS_KEYS[pendingAction]))
      setPendingAction(null)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t(FAILURE_KEYS[pendingAction]))
    } finally {
      setBusy(false)
    }
  }

  async function confirmOwnerAssignment() {
    if (!data) return
    setOwnerBusy(true)
    try {
      // `expect_unowned` is the backend's compare-and-set guard. It is sent as
      // FALSE only when this skill already has an owner - i.e. only for a real
      // transfer, which is the request explicitly saying "I know someone owns
      // this and I am taking it from them". For an unowned skill it stays true,
      // so a row that acquired an owner since this drawer was opened conflicts
      // (409) instead of being silently overwritten.
      await api.post(`/v1/inventory/${skillId}/owner`, {
        owner: ownerDraft.trim(),
        reason: ownerReason.trim(),
        expect_unowned: data.owner === null,
      })
      reload()
      toast.success(t('inventory.ownerAssignSucceeded'))
      setOwnerConfirming(false)
      setOwnerDraft('')
      setOwnerReason('')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('inventory.ownerAssignFailed'))
    } finally {
      setOwnerBusy(false)
    }
  }

  // Memoized so its identity is stable across re-renders while the modal is
  // open/busy - ConfirmModal's focus-management effect is keyed on
  // [open, onCancel], and a new closure here every render would tear
  // down/re-run that effect on every re-render, causing a focus flicker.
  const cancelAction = useCallback(() => setPendingAction(null), [])
  const cancelOwnerAssignment = useCallback(() => setOwnerConfirming(false), [])

  return (
    <DataState loading={loading} error={error}>
      {data && (
        <>
          <div className="summary-grid">
            <div className="summary-stat">
              {/* Was the RAW wire value: this tile showed "blocked"/"scanning"
                  in English while the list one click away showed the
                  translated label for the same skill. */}
              <div className="value">
                <LifecycleBadge state={data.state} />
              </div>
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
            <div className="summary-stat">
              {/* Absence is spelled out, not left as a blank cell: "no owner
                  on record" is the reason nobody but an admin can ship a new
                  version of this skill, and without it the 403 that follows
                  looks like a bug rather than a state. */}
              <div className="value">
                {data.owner ?? <span className="hint">{t('inventory.ownerNone')}</span>}
              </div>
              <div className="label">{t('inventory.statOwner')}</div>
            </div>
          </div>
          {data.owner === null && <p className="hint">{t('inventory.ownerNoneHint')}</p>}
          {isAdmin && (
            <div className="card">
              <label>
                {t('common.reason')}
                <input value={reason} onChange={(e) => setReason(e.target.value)} />
              </label>{' '}
              {/* SECURITY/UX: every button below is gated on the same source
                  states the backend's VALID_TRANSITIONS actually accepts
                  (lifecycle.py) - quarantine only from `published`, restore
                  only from `quarantined`, retire from RETIRE_ELIGIBLE_STATES
                  (derived above, everything except `submitted`/`retired`).
                  Offering any of these off their state would just earn the
                  admin a 409; a quarantined skill shows Restore, not a second
                  Quarantine, and a just-restored (now `published`) skill goes
                  back to offering Quarantine like any other published
                  skill. */}
              {data.state === 'published' && (
                <button className="danger" onClick={() => setPendingAction('quarantine')}>
                  {t('inventory.quarantine')}
                </button>
              )}{' '}
              {data.state === 'quarantined' && (
                <button className="danger" onClick={() => setPendingAction('restore')}>
                  {t('inventory.restore')}
                </button>
              )}{' '}
              {data.state !== null && RETIRE_ELIGIBLE_STATES.has(data.state) && (
                <button className="danger" onClick={() => setPendingAction('retire')}>
                  {t('inventory.retire')}
                </button>
              )}
              {data.state === 'quarantined' && <p className="hint">{t('inventory.restoreHint')}</p>}
            </div>
          )}
          {isAdmin && (
            <div className="card">
              <h2>{t('inventory.ownerHeading')}</h2>
              {/* Two different acts behind one endpoint, and the UI says which
                  one this is. Assigning an owner to an unowned skill gives
                  authority nobody currently holds; a transfer TAKES it from
                  someone. The second is not offered as the same neutral
                  "save". */}
              <p className="hint">
                {data.owner === null
                  ? t('inventory.ownerAssignHint')
                  : t('inventory.ownerTransferHint', { owner: data.owner })}
              </p>
              <div className="inline-form">
                <label>
                  {t('inventory.ownerLabel')}
                  <input
                    value={ownerDraft}
                    onChange={(e) => setOwnerDraft(e.target.value)}
                    placeholder={t('inventory.ownerPlaceholder')}
                  />
                </label>
                <label>
                  {t('common.reason')}
                  <input value={ownerReason} onChange={(e) => setOwnerReason(e.target.value)} />
                </label>
                <button
                  type="button"
                  className={data.owner === null ? 'primary' : 'danger'}
                  disabled={ownerDraft.trim() === '' || ownerReason.trim() === '' || ownerBusy}
                  onClick={() => setOwnerConfirming(true)}
                >
                  {data.owner === null
                    ? t('inventory.ownerAssign')
                    : t('inventory.ownerTransfer')}
                </button>
              </div>
              <p className="hint">{t('inventory.ownerExactHint')}</p>
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
                : pendingAction === 'restore'
                  ? t('inventory.confirmRestoreTitle')
                  : t('inventory.confirmRetireTitle')
            }
            description={t('inventory.confirmDescription', { skillId })}
            danger
            busy={busy}
            onConfirm={confirmTransition}
            onCancel={cancelAction}
          />
          <ConfirmModal
            open={ownerConfirming}
            title={
              data.owner === null
                ? t('inventory.confirmOwnerAssignTitle')
                : t('inventory.confirmOwnerTransferTitle')
            }
            description={
              data.owner === null
                ? t('inventory.confirmOwnerAssignDescription', {
                    skillId,
                    owner: ownerDraft.trim(),
                  })
                : t('inventory.confirmOwnerTransferDescription', {
                    skillId,
                    from: data.owner,
                    to: ownerDraft.trim(),
                  })
            }
            // A transfer revokes someone's authority - it gets the danger
            // styling; a first assignment takes nothing from anyone.
            danger={data.owner !== null}
            busy={ownerBusy}
            onConfirm={confirmOwnerAssignment}
            onCancel={cancelOwnerAssignment}
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
