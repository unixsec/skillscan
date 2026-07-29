import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n/I18nContext'
import { AuditPage } from './Audit'
import type { AuditEntrySummary } from '../api/types'

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }))

vi.mock('../api/client', () => {
  class ApiError extends Error {
    detail: string
    constructor(detail: string) {
      super(detail)
      this.detail = detail
    }
  }
  class SessionExpiredError extends ApiError {}
  return {
    api: { get: mockGet },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

const PAGE_SIZE = 100

function entry(seq: number): AuditEntrySummary {
  return {
    seq,
    operator: `op-${seq}`,
    action: 'scan.decided',
    payload: {},
    chained_at: '2026-07-29T02:00:00Z',
  }
}

// Ascending seq, exactly as both branches of audit/router.py return them.
function page(firstSeq: number, count: number): AuditEntrySummary[] {
  return Array.from({ length: count }, (_, i) => entry(firstSeq + i))
}

function respondWith(entries: AuditEntrySummary[], chainValid = true) {
  mockGet.mockResolvedValue({ chain_valid: chainValid, entries })
}

function renderAudit() {
  render(
    <I18nProvider>
      <AuditPage />
    </I18nProvider>,
  )
}

function lastRequestedUrl(): string {
  return mockGet.mock.calls[mockGet.mock.calls.length - 1][0] as string
}

function clickOlder() {
  fireEvent.click(screen.getByRole('button', { name: '更早' }))
}

function clickNewer() {
  fireEvent.click(screen.getByRole('button', { name: '更晚' }))
}

// No stored locale in this environment, so I18nProvider falls back to its
// default (zh) - the assertions below are against the Chinese strings.
describe('AuditPage cursor pagination', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('asks for an explicit page size instead of relying on the backend default', async () => {
    // The bug: no parameters at all, so `_DEFAULT_LIMIT = 100` silently capped
    // the whole page at the 100 newest rows of a ~3000-row ledger.
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')
    expect(lastRequestedUrl()).toContain(`limit=${PAGE_SIZE}`)
  })

  it('sends no since_seq on the newest page', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')
    expect(lastRequestedUrl()).not.toContain('since_seq')
  })

  it('steps the cursor a page backwards through the chain', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')

    respondWith(page(301, PAGE_SIZE))
    clickOlder()
    await waitFor(() => expect(lastRequestedUrl()).toContain('since_seq=301'))
    expect(await screen.findByText('301')).toBeInTheDocument()
  })

  it('never steps past the genesis entry', async () => {
    respondWith(page(40, 20))
    renderAudit()
    await screen.findByText('40')

    respondWith(page(1, 39))
    clickOlder()
    // 40 - 100 is negative; the cursor clamps to the chain's root of trust.
    await waitFor(() => expect(lastRequestedUrl()).toContain('since_seq=1'))
    // ...and once the window starts at genesis there is nothing older left.
    await waitFor(() => expect(screen.getByRole('button', { name: '更早' })).toBeDisabled())
  })

  it('keeps making progress even if the seq column has a page-wide gap', async () => {
    // `seq` is autoincrement on an append-only table, but a rolled-back append
    // can still burn a value. Stepping the REQUESTED cursor rather than the
    // returned first row is what stops a wide gap from serving the same rows
    // forever.
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')

    respondWith(page(401, PAGE_SIZE)) // gap: nothing exists below seq 401
    clickOlder()
    await waitFor(() => expect(lastRequestedUrl()).toContain('since_seq=301'))

    clickOlder()
    // Strictly decreasing, not stuck at 301.
    await waitFor(() => expect(lastRequestedUrl()).toContain('since_seq=201'))
  })

  it('walks forward from the last seq on the page', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')

    respondWith(page(301, PAGE_SIZE))
    clickOlder()
    await screen.findByText('301')

    respondWith(page(401, PAGE_SIZE))
    clickNewer()
    // 301..400 was a full page, so forward means "the entry after 400".
    await waitFor(() => expect(lastRequestedUrl()).toContain('since_seq=401'))
  })

  it('returns to the live newest view rather than paging past the tail', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')

    respondWith(page(301, 40)) // short page = the tail is already on screen
    clickOlder()
    await screen.findByText('301')

    respondWith(page(401, PAGE_SIZE))
    clickNewer()
    // Not `since_seq=341`, which would serve an empty page the user then has
    // to back out of.
    await waitFor(() => expect(lastRequestedUrl()).not.toContain('since_seq'))
  })

  it('offers nothing newer while the newest page is showing', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')
    expect(screen.getByRole('button', { name: '更晚' })).toBeDisabled()
  })

  it('hides the pager entirely when the whole ledger fits on one page', async () => {
    respondWith(page(1, 12))
    renderAudit()
    await screen.findByText('12')
    expect(screen.queryByRole('button', { name: '更早' })).toBeNull()
    expect(screen.queryByRole('button', { name: '更晚' })).toBeNull()
  })

  it('names the seq range on screen rather than an invented page number', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')
    expect(screen.getByText('第 401 – 500 条')).toBeInTheDocument()
  })

  it('states the chain check covers the whole ledger, on every page', async () => {
    // Task 17: this line used to say the opposite - that a paged check was
    // incremental and anchored on the cursor - because it was. The backend no
    // longer offers that weaker answer, so the badge means the same thing on
    // page 1 and on page 30, and the scope has to be stated on both.
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')
    expect(screen.getByText(/链校验覆盖整个账本/)).toBeInTheDocument()

    respondWith(page(301, PAGE_SIZE))
    clickOlder()
    await screen.findByText('301')
    expect(screen.getByText(/链校验覆盖整个账本/)).toBeInTheDocument()
    // ...and nothing on screen weakens it to "this page only".
    expect(screen.queryByText(/增量校验/)).toBeNull()
  })

  it('says the filters only see the current page', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')
    expect(screen.getByText(/筛选仅作用于当前页的 100 条记录/)).toBeInTheDocument()
  })

  it('leaves an empty page escapable in both directions', async () => {
    respondWith(page(401, PAGE_SIZE))
    renderAudit()
    await screen.findByText('401')

    respondWith([])
    clickOlder()
    // No rows to derive a cursor from - the pager still has to work, so it is
    // driven by the requested window rather than by the response.
    await waitFor(() => expect(screen.getByText('本页无记录')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: '更早' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '更晚' })).toBeEnabled()
  })

  it('still renders each entry it was given', async () => {
    respondWith([entry(401), entry(402)])
    renderAudit()
    const table = await screen.findByRole('table')
    expect(within(table).getByText('401')).toBeInTheDocument()
    expect(within(table).getByText('op-402')).toBeInTheDocument()
  })
})
