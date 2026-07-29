import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, ApiError } from '../../api/client'
import { useApiData } from '../../api/useApiData'
import { DataState } from '../../components/DataState'
import { ConfirmModal } from '../../components/Modal'
import { Pager } from '../../components/Pager'
import { TableFilterBar, useTableFilter } from '../../components/TableFilter'
import type { FilterField } from '../../components/TableFilter'
import { useToast } from '../../components/Toast'
import { useI18n } from '../../i18n/I18nContext'
import { LifecycleBadge } from '../Inventory'
import type { OwnerAssignmentResult, UnownedSkill, UnownedSkillPage } from '../../api/types'

// Matches the backend's own default window (`inventory/router.py`'s
// `_UNOWNED_DEFAULT_LIMIT`); its clamp is 200, so this stays well inside it.
// The deployed VM has ~481 unowned skills, which is exactly why this page
// pages at all instead of rendering one unbounded table.
const PAGE_SIZE = 100

// `inventory/router.py`'s `_MAX_BULK_ASSIGNMENTS`. Mirrored here so a
// too-large selection is refused with a sentence instead of a 422 - the same
// "small closed constant, safe to duplicate, backend is still the authority"
// call `admin/Users.tsx` makes for the role list.
const MAX_BULK = 200

export function AdminOwnershipPage() {
  const { t } = useI18n()
  const toast = useToast()
  const [page, setPage] = useState(1)
  const { data, loading, error, reload } = useApiData<UnownedSkillPage>(
    () =>
      api.get(
        `/v1/inventory/ownership/unowned?limit=${PAGE_SIZE}&offset=${(page - 1) * PAGE_SIZE}`,
      ),
    [page],
  )
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [owner, setOwner] = useState('')
  const [reason, setReason] = useState('')
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [failures, setFailures] = useState<OwnerAssignmentResult['failed']>([])
  // The advisory from the last assignment - see `confirmAssign`. Null when the
  // identity was recognized, or before any assignment has run.
  const [ownerNotice, setOwnerNotice] = useState<string | null>(null)

  const skills = useMemo(() => data?.skills ?? [], [data])
  const total = data?.total ?? 0

  // A selection is only meaningful for rows the admin can currently SEE. Ids
  // survive a page turn perfectly well, but assigning ownership of skills that
  // scrolled out of view is the opposite of the deliberate, evidence-in-front-
  // of-you act this page exists to support.
  useEffect(() => {
    setSelectedIds(new Set())
    setFailures([])
    setOwnerNotice(null)
  }, [page])

  const filterFields: FilterField<UnownedSkill>[] = useMemo(
    () => [
      {
        key: 'genesis_actor',
        label: t('ownership.colGenesisActor'),
        value: (row) => row.genesis_actor ?? '',
      },
      { key: 'source', label: t('ownership.colSource'), value: (row) => row.source },
      {
        key: 'trust_tier',
        label: t('ownership.colTrustTier'),
        value: (row) => row.trust_tier,
        renderOption: (v) => {
          const key = `trustTier.${v}`
          const translated = t(key)
          return translated === key ? v : translated
        },
      },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(skills, filterFields)

  const visibleIds = useMemo(() => filtered.map((s) => s.skill_id), [filtered])
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedIds.has(id))

  function toggleOne(skillId: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(skillId)) next.delete(skillId)
      else next.add(skillId)
      return next
    })
  }

  function toggleAllVisible() {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (allVisibleSelected) visibleIds.forEach((id) => next.delete(id))
      else visibleIds.forEach((id) => next.add(id))
      return next
    })
  }

  const selectedList = useMemo(() => [...selectedIds], [selectedIds])
  const canAssign =
    selectedList.length > 0 &&
    selectedList.length <= MAX_BULK &&
    owner.trim() !== '' &&
    reason.trim() !== ''

  async function confirmAssign() {
    setBusy(true)
    try {
      const result = await api.post<OwnerAssignmentResult>('/v1/inventory/ownership/assign', {
        owner: owner.trim(),
        reason: reason.trim(),
        skill_ids: selectedList,
      })
      setFailures(result.failed)
      setConfirming(false)
      setSelectedIds(new Set())
      // ADVISORY, shown alongside the outcome and never instead of it: the rows
      // really were assigned. A typo in a free-text identity is the realistic
      // mistake on this page and it fails SILENTLY - the write succeeds, the
      // skills stay admin-only because the backend compares verbatim, and
      // nobody learns otherwise until the real owner's next submission 403s.
      // Kept as its own notice rather than folded into the success toast, since
      // "assigned 40 skills" is still true and must not read as a failure.
      setOwnerNotice(
        result.owner_recognized === false
          ? t('ownership.ownerUnrecognized', { owner: result.owner })
          : result.owner_recognized === null
            ? t('ownership.ownerRecognitionUnavailable', { owner: result.owner })
            : null,
      )
      if (result.failed.length === 0) {
        toast.success(t('ownership.assignSucceeded', { count: result.assigned.length }))
      } else {
        // Partial success is stated, never rounded to "done". Each failure is
        // a real row that still has no owner, and the admin has to see which.
        toast.error(
          t('ownership.assignPartial', {
            assigned: result.assigned.length,
            failed: result.failed.length,
          }),
        )
      }
      // Back to the first page on purpose: the assigned rows have just LEFT
      // this list, so every offset behind them shifted and staying on page 3
      // would silently skip rows. It also matches how the job is actually
      // worked - page 1 refills with the next unassigned skills each time.
      if (page === 1) reload()
      else setPage(1)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : t('ownership.assignFailed'))
    } finally {
      setBusy(false)
    }
  }

  const cancelAssign = useCallback(() => setConfirming(false), [])

  return (
    <div>
      <h1>{t('ownership.title')}</h1>
      <p className="hint">{t('ownership.description')}</p>
      {/* The distinction this whole page is built around, said out loud where
          the person making the decision will read it. The genesis actor column
          is evidence; there is deliberately no button that turns it into the
          answer. */}
      <p className="hint">{t('ownership.evidenceWarning')}</p>

      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (canAssign) setConfirming(true)
        }}
      >
        <label>
          {t('ownership.ownerLabel')}
          <input
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder={t('ownership.ownerPlaceholder')}
          />
        </label>
        <label>
          {t('common.reason')}
          <input value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <button type="submit" className="primary" disabled={!canAssign || busy}>
          {t('ownership.assignSelected', { count: selectedList.length })}
        </button>
      </form>
      {/* Typing an identity that does not exist is the realistic mistake here,
          and its failure mode is worth stating: it fails CLOSED (the skill
          stays admin-only) rather than granting anyone anything. */}
      <p className="hint">{t('ownership.ownerExactHint')}</p>
      {selectedList.length > MAX_BULK && (
        <p className="hint">{t('ownership.tooManySelected', { max: MAX_BULK })}</p>
      )}
      {/* Deliberately `hint`, not `error`: nothing failed. The assignment is
          done and correct; this is the one thing the system can notice about a
          typo that would otherwise stay silent until someone else's 403. */}
      {ownerNotice !== null && <p className="hint">{ownerNotice}</p>}

      {failures.length > 0 && (
        <div className="card">
          <h2>{t('ownership.failuresHeading')}</h2>
          <table>
            <thead>
              <tr>
                <th>{t('ownership.colSkillId')}</th>
                <th>{t('ownership.colError')}</th>
              </tr>
            </thead>
            <tbody>
              {failures.map((f) => (
                <tr key={f.skill_id}>
                  <td>{f.skill_id}</td>
                  <td>{f.error}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <DataState loading={loading} error={error} empty={total === 0}>
        <p className="hint">{t('ownership.total', { total })}</p>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        <table>
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  aria-label={t('ownership.selectAll')}
                  checked={allVisibleSelected}
                  onChange={toggleAllVisible}
                />
              </th>
              <th>{t('ownership.colSkillId')}</th>
              <th>{t('ownership.colGenesisActor')}</th>
              <th>{t('ownership.colSource')}</th>
              <th>{t('ownership.colTrustTier')}</th>
              <th>{t('ownership.colState')}</th>
              <th>{t('ownership.colCreated')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.skill_id}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={s.skill_id}
                    checked={selectedIds.has(s.skill_id)}
                    onChange={() => toggleOne(s.skill_id)}
                  />
                </td>
                <td>{s.skill_id}</td>
                <td>
                  {s.genesis_actor ?? <span className="hint">{t('ownership.noGenesisActor')}</span>}
                </td>
                <td>{s.source}</td>
                <td>{s.trust_tier}</td>
                <td>
                  {/* Was the raw wire value ("published"/"blocked" in English
                      regardless of locale) - the same bug c7e9bcd fixed in the
                      inventory detail tile, reintroduced here in a new table.
                      LifecycleBadge is the one place that translates and
                      colours a lifecycle state; see lifecycleStateGuard.test.ts. */}
                  <LifecycleBadge state={s.state} />
                </td>
                <td>{new Date(s.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
      {/* Outside DataState: `total` is authoritative, so a page that comes back
          empty because rows were assigned underneath it must still offer a way
          back rather than dead-ending on "no data". */}
      <Pager
        page={page}
        pageCount={total > 0 ? Math.max(1, Math.ceil(total / PAGE_SIZE)) : null}
        onChange={setPage}
      />

      <ConfirmModal
        open={confirming}
        title={t('ownership.confirmTitle')}
        description={t('ownership.confirmDescription', {
          count: selectedList.length,
          owner: owner.trim(),
        })}
        busy={busy}
        onConfirm={confirmAssign}
        onCancel={cancelAssign}
      />
    </div>
  )
}
