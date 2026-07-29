import { useMemo, useState } from 'react'
import { api } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { BoolBadge } from '../components/Badge'
import { CursorPager } from '../components/Pager'
import { TableFilterBar, useTableFilter } from '../components/TableFilter'
import type { FilterField } from '../components/TableFilter'
import { useI18n } from '../i18n/I18nContext'
import type { AuditEntrySummary } from '../api/types'

// BUG (milestone F Task 9): this page called /v1/audit with no parameters
// against `_DEFAULT_LIMIT = 100` (audit/router.py), so on a ledger of any real
// size - the VM's was already ~3000 rows - only the most recent 100 entries
// existed as far as the console was concerned.
//
// The endpoint pages by CURSOR, not by offset: its only positional parameter is
// `since_seq`, "entries with seq >= this, ascending". That is the append-only
// chain's own read direction and this page follows it rather than bending it
// into page numbers, which would name different rows every time an entry is
// appended.
const PAGE_SIZE = 100

export function AuditPage() {
  const { t } = useI18n()
  // null = the live newest page: with no `since_seq` the backend deliberately
  // returns the most recent PAGE_SIZE entries (audit/router.py explains why
  // "oldest first" is useless as an audit-log default). `since_seq` now pages
  // the read ONLY - the chain verification behind `chain_valid` is genesis-
  // rooted on every request, whichever page was asked for (Task 17).
  const [sinceSeq, setSinceSeq] = useState<number | null>(null)
  const { data, loading, error } = useApiData<{
    chain_valid: boolean
    entries: AuditEntrySummary[]
  }>(
    () =>
      api.get(
        sinceSeq === null
          ? `/v1/audit?limit=${PAGE_SIZE}`
          : `/v1/audit?since_seq=${sinceSeq}&limit=${PAGE_SIZE}`,
      ),
    [sinceSeq],
  )
  const entries = useMemo(() => data?.entries ?? [], [data])
  const filterFields: FilterField<AuditEntrySummary>[] = useMemo(
    () => [
      { key: 'action', label: t('audit.colAction'), value: (row) => row.action },
      { key: 'operator', label: t('audit.colOperator'), value: (row) => row.operator },
    ],
    [t],
  )
  const { filtered, options, selected, setSelected } = useTableFilter(entries, filterFields)

  // Entries always arrive in ascending seq order, whichever branch served them.
  const firstSeq = entries[0]?.seq
  const lastSeq = entries[entries.length - 1]?.seq
  // The window we ASKED for, not the window we got back. Stepping the request
  // cursor rather than the returned `firstSeq` is what makes "older" terminate:
  // `seq` is an autoincrement column on a table nothing ever deletes from, but
  // a rolled-back append can still burn a value, and a gap wide enough to span
  // a whole page would otherwise return the same rows forever. This way each
  // click strictly decreases the cursor by PAGE_SIZE until it reaches genesis.
  const windowStart = sinceSeq ?? firstSeq ?? 1
  // seq 1 is the genesis entry (audit/service.py calls it the chain's root of
  // trust), so there is nothing older once the window starts there.
  const hasOlder = windowStart > 1
  const hasNewer = sinceSeq !== null

  function goOlder() {
    setSinceSeq(Math.max(1, windowStart - PAGE_SIZE))
  }

  function goNewer() {
    // A short page means the tail of the chain is already on screen, so the
    // step forward is back to the live newest view - not a `since_seq` past the
    // end, which returns an empty page the user then has to back out of.
    if (lastSeq === undefined || entries.length < PAGE_SIZE) {
      setSinceSeq(null)
      return
    }
    setSinceSeq(lastSeq + 1)
  }

  return (
    <div>
      <h1>{t('audit.title')}</h1>
      {/* The badge is a WHOLE-LEDGER claim and the line under it says so, on
          every page, not just while paging. It used to be weaker than it looked:
          verify_chain took the page cursor and anchored on the entry at it, so a
          rewrite of anything older went unseen while the badge still read
          "intact". The backend no longer offers that answer (audit/service.py
          Task 17) - the scope statement here exists so the badge cannot be read
          as "this page is fine" either. */}
      {data && (
        <>
          <p>
            {t('audit.chainStatus')}
            <BoolBadge value={!data.chain_valid} trueLabel={t('audit.tampered')} falseLabel={t('audit.valid')} />
          </p>
          <p className="hint">{t('audit.chainScope')}</p>
        </>
      )}
      <DataState loading={loading} error={error} empty={entries.length === 0}>
        <TableFilterBar
          fields={filterFields}
          options={options}
          selected={selected}
          onChange={setSelected}
        />
        {/* The filters run in the browser over this page's rows only - an empty
            filtered table means "none on this page", never "none in the
            ledger". */}
        {(hasOlder || hasNewer) && (
          <p className="hint">{t('pager.filterScopeHint', { count: entries.length })}</p>
        )}
        <table>
          <thead>
            <tr>
              <th>{t('audit.colSeq')}</th>
              <th>{t('audit.colOperator')}</th>
              <th>{t('audit.colAction')}</th>
              <th>{t('audit.colWhen')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.seq}>
                <td>{e.seq}</td>
                <td>{e.operator}</td>
                <td>
                  <code>{e.action}</code>
                </td>
                <td>{new Date(e.chained_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </DataState>
      {/* Outside DataState so an empty page is still escapable in both
          directions. */}
      <CursorPager
        status={
          firstSeq === undefined || lastSeq === undefined
            ? t('audit.noEntriesOnPage')
            : t('audit.seqRange', { first: firstSeq, last: lastSeq })
        }
        hasOlder={hasOlder}
        hasNewer={hasNewer}
        onOlder={goOlder}
        onNewer={goNewer}
      />
    </div>
  )
}
