import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { Drawer } from '../components/Drawer'
import { FileField } from '../components/FileField'
import { Pager } from '../components/Pager'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useToast } from '../components/Toast'
import { ScoreBadge, VerdictBadge } from '../components/Badge'
import { hasAnyRole, useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'
import { ingestErrorMessage } from '../i18n/ingestErrors'
import { submitterNames } from '../api/types'
import type { InventoryDetail, ScanSummary } from '../api/types'
import { ScanDetailContent } from './ScanDetail'
import { scanStateLabel, TERMINAL_SCAN_STATES } from '../scanState'

// TERMINAL_SCAN_STATES (see scanState.ts for the backend evidence): the list
// keeps polling as long as ANY row on the current page is still non-terminal
// - in particular the row a just-completed submit() below adds - and stops
// once every visible scan has settled.

// BUG (milestone F Task 9): this page called /v1/scans with no parameters
// against a backend default of `limit=50` (gateway/router.py's `list_scans`),
// so scan 51 onwards was unreachable through the console - not hidden behind a
// filter, simply absent, with nothing on the page to suggest more existed.
//
// The endpoint takes `limit` (clamped to 200) + `offset` and returns no total
// count, so this is a real server-side window: one page per request, and the
// only honest thing the pager can say is which page you are on.
const PAGE_SIZE = 50

// How long the skill_id field has to settle before the registration lookup
// below fires. Long enough that typing a 30-character skill_id is one request,
// short enough that the answer arrives before the user reaches the tier
// control.
const SKILL_LOOKUP_DEBOUNCE_MS = 400

// What `POST /v1/scans` accepts: tar (any compression `tarfile` opens with
// "r:*") and, since 2026-07-30, zip - both marketplaces this system integrates
// with distribute zip. Extensions plus MIME types, because a browser's file
// dialog filters on whichever of the two the platform understands.
const ARCHIVE_ACCEPT =
  '.tar,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.zip,application/x-tar,application/gzip,application/zip'

export function ScansPage() {
  const { t } = useI18n()
  const toast = useToast()
  const { session } = useSession()
  const [searchParams, setSearchParams] = useSearchParams()
  const detailScanId = searchParams.get('detail')
  const [page, setPage] = useState(1)
  // Over-fetch by exactly one row: with no total in the response, asking for
  // PAGE_SIZE + 1 is the only way to learn whether a next page exists without
  // a second round trip. The extra row is never rendered.
  const { data, loading, error, pollError, reload } = useApiData<{ items: ScanSummary[] }>(
    () => api.get(`/v1/scans?limit=${PAGE_SIZE + 1}&offset=${(page - 1) * PAGE_SIZE}`),
    [page],
    { pollWhile: (d) => d.items.some((item) => !TERMINAL_SCAN_STATES.has(item.state)) },
  )
  const [file, setFile] = useState<File | null>(null)
  const [skillId, setSkillId] = useState('')
  const [trustTier, setTrustTier] = useState('internal')
  const [submitting, setSubmitting] = useState(false)
  // 里程碑 F Task 15 step 4: the RECORDED trust tier of the skill_id currently
  // typed, or null when it is not a registered skill (or not knowable here).
  const [recordedTier, setRecordedTier] = useState<string | null>(null)

  // WHY THIS LOOKUP EXISTS. `trust_tier` is only honoured for a FIRST
  // registration. On a resubmission of an already-registered skill_id the
  // backend overwrites it with the skill's RECORDED tier
  // (gateway/router.py, closing finding I2 - otherwise any submitter could
  // re-judge a `public` skill as `internal` and downgrade a finding that had
  // to block). This form kept offering the control anyway, so on every
  // resubmission the user was choosing a value that was silently discarded.
  //
  // WHY IT IS ROLE-GATED. `GET /v1/inventory/{skill_id}` requires
  // approver/auditor/admin, and that is deliberately NOT widened for this: a
  // lookup any submitter could call would turn "does this skill_id exist, and
  // at what tier" into a cheap enumeration probe. Nothing new is exposed here
  // - these roles can already read the whole inventory. A submitter gets the
  // standing hint below instead, which is true in both cases and never lies
  // about what the control does.
  const canReadInventory = hasAnyRole(session, 'approver', 'auditor', 'admin')
  useEffect(() => {
    const trimmed = skillId.trim()
    if (!trimmed || !canReadInventory) {
      setRecordedTier(null)
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      api
        .get<InventoryDetail>(`/v1/inventory/${encodeURIComponent(trimmed)}`)
        .then((detail) => {
          if (!cancelled) setRecordedTier(detail.trust_tier)
        })
        .catch(() => {
          // A 404 is the ordinary answer for a brand-new skill_id, and any
          // other failure must not leave a STALE tier on screen claiming this
          // submission is a resubmission. Unknown means "treat it as new" -
          // which re-enables the control, i.e. fails towards showing the user
          // a control that might be ignored rather than hiding one that works.
          if (!cancelled) setRecordedTier(null)
        })
    }, SKILL_LOOKUP_DEBOUNCE_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [skillId, canReadInventory])

  const isResubmission = recordedTier !== null

  const fetched = useMemo(() => data?.items ?? [], [data])
  const hasNext = fetched.length > PAGE_SIZE
  const items = useMemo(() => fetched.slice(0, PAGE_SIZE), [fetched])
  const filterFields: FilterField<ScanSummary>[] = useMemo(
    () => [
      {
        key: 'state',
        label: t('scans.colState'),
        value: (row) => row.state,
        renderOption: (v) => scanStateLabel(t, v),
      },
      // 里程碑 F Task 16: ALL submitters, not the first one. Filtering on
      // `row.submitter` alone hid a deduplicated scan from the very person who
      // submitted it whenever someone else got there first - and their own scan
      // list is the only way they reach it through the UI.
      {
        key: 'submitter',
        label: t('scans.colSubmitter'),
        value: (row) => submitterNames(row),
      },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(items, filterFields)

  function openDetail(e: React.MouseEvent, scanId: string) {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.set('detail', scanId)
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

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    if (!file) {
      toast.error(t('scans.noFileError'))
      return
    }
    setSubmitting(true)
    try {
      const form = new FormData()
      form.append('package', file)
      // Optional inventory registration: naming a skill_id makes this
      // submission enter the lifecycle state machine (visible on Inventory).
      if (skillId.trim()) {
        form.append('skill_id', skillId.trim())
        // Sends what the form SHOWS. On a resubmission that is the skill's
        // recorded tier, so the value the backend is going to use anyway - the
        // request no longer carries a contradictory number that gets silently
        // discarded. The backend still decides; this only stops the client
        // from asserting something it knows to be untrue.
        form.append('trust_tier', recordedTier ?? trustTier)
      }
      await api.postForm('/v1/scans', form)
      setFile(null)
      setSkillId('')
      // The new scan is the newest row, so it lands on page 1 - go there rather
      // than refreshing whichever page the user happens to be on, where the
      // submission they just made would be nowhere to be seen. Changing the
      // page already triggers the refetch; reload() would only double it.
      if (page === 1) reload()
      else setPage(1)
      toast.success(t('scans.submitSucceeded'))
    } catch (err) {
      // `ingestErrorMessage` translates the archive-rejection 400 and returns
      // every other detail unchanged - a 403/409/503 from this endpoint is
      // already a sentence, and inventing a translation for a string it does not
      // recognize is how a confidently wrong message gets shown.
      toast.error(
        err instanceof ApiError ? ingestErrorMessage(t, err.detail) : t('scans.submitFailed'),
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <h1>{t('scans.title')}</h1>
      <form className="inline-form" onSubmit={handleSubmit}>
        {/* `accept` was missing entirely (the component has always supported
            it), so the native dialog offered every file on disk for an endpoint
            that takes exactly two container formats. A hint only - the backend
            dispatches on MAGIC BYTES and never on the filename, so a renamed
            file is still judged by what it actually is. */}
        <FileField
          label={t('scans.packageLabel')}
          accept={ARCHIVE_ACCEPT}
          file={file}
          onSelect={setFile}
        />
        <label>
          {t('scans.skillIdLabel')}
          <input
            value={skillId}
            onChange={(e) => setSkillId(e.target.value)}
            placeholder={t('scans.skillIdPlaceholder')}
          />
        </label>
        {skillId.trim() && (
          <label>
            {t('scans.trustTierLabel')}
            {/* DISABLED on a resubmission, because the backend ignores it
                there and judges at the skill's recorded tier. A control that
                does nothing is worse than no control: it tells the user they
                made a choice. The value shown is the tier that will ACTUALLY
                be used, not the one they last picked. */}
            <select
              value={recordedTier ?? trustTier}
              disabled={isResubmission}
              onChange={(e) => setTrustTier(e.target.value)}
            >
              <option value="internal">{t('trustTier.internal')}</option>
              <option value="partner">{t('trustTier.partner')}</option>
              <option value="public">{t('trustTier.public')}</option>
            </select>
          </label>
        )}
        <button type="submit" className="primary" disabled={submitting}>
          {submitting ? t('scans.submitting') : t('scans.submit')}
        </button>
      </form>
      {skillId.trim() &&
        (isResubmission ? (
          <p className="hint">
            {t('scans.trustTierLockedHint', {
              tier: (() => {
                const key = `trustTier.${recordedTier}`
                const translated = t(key)
                return translated === key ? (recordedTier ?? '') : translated
              })(),
            })}
          </p>
        ) : (
          // Shown to everyone, including the submitters who cannot do the
          // lookup above: true whichever case this turns out to be, so it
          // never claims the control matters when it does not.
          <p className="hint">{t('scans.trustTierFirstOnlyHint')}</p>
        ))}
      {/* Outside DataState, and not routed through it: a failed background
          refresh leaves the table on screen (it is still the last real answer
          the server gave) with a note that it may have stopped advancing.
          Passing it as `error` would blank the whole list for one blip. */}
      {pollError !== null && (
        <p className="hint">{t('common.refreshFailed', { message: pollError })}</p>
      )}
      <DataState loading={loading} error={error} empty={items.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        {/* Said out loud because the alternative is a silent wrong answer: the
            filters run in the browser over the rows of the CURRENT page only.
            Filtering by BLOCK and seeing nothing means "none on this page",
            not "none exist", and without this line there is no way to tell
            those apart. */}
        {(page > 1 || hasNext) && (
          <p className="hint">{t('pager.filterScopeHint', { count: items.length })}</p>
        )}
        <table>
          <thead>
            <tr>
              <th>{t('scans.colScanId')}</th>
              <th>{t('scans.colSkillName')}</th>
              <th>{t('scans.colSkillId')}</th>
              <th>{t('scans.colState')}</th>
              <th>{t('scans.colVerdict')}</th>
              <th>{t('scans.colScore')}</th>
              <th>{t('scans.colSubmitter')}</th>
              <th>{t('scans.colContentHash')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr key={s.scan_id}>
                <td>
                  <Link to={`/scans/${s.scan_id}`} onClick={(e) => openDetail(e, s.scan_id)}>
                    {s.scan_id.slice(0, 8)}…
                  </Link>
                </td>
                <td>{s.skill_name ?? <span className="hint">{t('scans.noSkillName')}</span>}</td>
                <td>{s.skill_id ?? <span className="hint">{t('scans.noSkillId')}</span>}</td>
                <td>{scanStateLabel(t, s.state)}</td>
                <td>
                  <VerdictBadge verdict={s.verdict} />
                </td>
                <td>
                  <ScoreBadge score={s.score} verdict={s.verdict} />
                </td>
                {/* 里程碑 F Task 16: every rightful submitter, not just
                    `ScanJob.submitter`. Byte-identical submissions collapse
                    onto one scan_job, so that one name is a STRANGER'S to
                    everyone who submitted afterwards - this table showed them
                    somebody else as the owner of their own scan, with the
                    correct names only in the detail drawer. */}
                <td>{submitterNames(s).join(', ')}</td>
                <td>
                  <code>{s.content_hash.slice(0, 12)}…</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
      {/* Outside DataState on purpose: a page that comes back empty (rows
          shifted between clicks) would otherwise render "no data" with no way
          back to the page the user came from. */}
      <Pager page={page} pageCount={null} hasNext={hasNext} onChange={setPage} />
      <Drawer
        open={detailScanId !== null}
        title={detailScanId ? t('scanDetail.title', { scanId: detailScanId }) : ''}
        onClose={closeDrawer}
      >
        {detailScanId && <ScanDetailContent scanId={detailScanId} />}
      </Drawer>
    </div>
  )
}
