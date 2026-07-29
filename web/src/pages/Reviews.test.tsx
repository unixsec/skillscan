import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n/I18nContext'
import { ToastProvider } from '../components/Toast'
import { ReviewsPage } from './Reviews'
import type { ReviewScan } from '../api/types'

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }))

// useApiData imports ApiError/SessionExpiredError from the same module, so the
// mock has to stand in for the whole client surface, not just `api`.
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
    api: { get: mockGet, post: vi.fn() },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

const SCAN_ID = '3f2a1c7e-1111-2222-3333-444455556666'

function reviewScan(overrides: Partial<ReviewScan> = {}): ReviewScan {
  return {
    scan_id: SCAN_ID,
    content_hash: 'a'.repeat(64),
    verdict: 'REVIEW',
    reasons: ['findings_capped_forces_review'],
    issued_at: '2026-07-29T02:00:00Z',
    skill_id: 'demo-skill',
    submitter: 'alice',
    superseded: false,
    ...overrides,
  }
}

function renderReviews(scans: ReviewScan[] = [reviewScan()]) {
  mockGet.mockResolvedValue({ scans })
  render(
    <MemoryRouter>
      <I18nProvider>
        <ToastProvider>
          <ReviewsPage />
        </ToastProvider>
      </I18nProvider>
    </MemoryRouter>,
  )
}

// No stored locale in this environment, so I18nProvider falls back to its
// default (zh) - the assertions below are against the Chinese strings.
describe('ReviewsPage evidence link', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('links each pending scan to its own detail page', async () => {
    renderReviews()
    const link = await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    // The whole point of the task: an approver deciding from reason codes had
    // no route to the findings behind them.
    expect(link).toHaveAttribute('href', `/scans/${SCAN_ID}`)
  })

  it('opens the evidence in a new tab so typed decision reasons survive', async () => {
    renderReviews()
    const link = await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    // Decision reasons live in this page's local state; an in-place navigation
    // would discard every one of them.
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'))
  })

  it('keeps the full scan id reachable even though the label is truncated', async () => {
    renderReviews()
    const link = await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    expect(link).toHaveAttribute('title', SCAN_ID)
    expect(link.textContent).toContain(SCAN_ID.slice(0, 8))
  })

  it('still shows the submitter and decision time next to the link', async () => {
    renderReviews()
    await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    expect(screen.getByText(/提交者：alice/)).toBeInTheDocument()
  })

  // 里程碑 F Task 16: the queue used to render the scalar `ScanJob.submitter`,
  // the FIRST submitter. Byte-identical submissions collapse onto one scan_job,
  // so on a deduplicated scan that name is a stranger's to everyone who
  // submitted afterwards. It matters here more than on the scan list: SoD
  // forbids approving a scan you submitted, so a queue naming only one of
  // several could show an approver a decision the API will refuse them.
  it('names every submitter of a deduplicated scan, not just the first', async () => {
    renderReviews([reviewScan({ submitter: 'alice', submitters: ['alice', 'bob'] })])
    await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    expect(screen.getByText(/提交者：alice, bob/)).toBeInTheDocument()
  })

  it('falls back to the legacy scalar when the list did not come back', async () => {
    // A backend that predates the field. Never a guess - just the one name that
    // WAS on record.
    renderReviews([reviewScan({ submitter: 'carol', submitters: undefined })])
    await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    expect(screen.getByText(/提交者：carol/)).toBeInTheDocument()
  })

  it('says "unknown" rather than an empty name when nothing was recorded', async () => {
    renderReviews([reviewScan({ submitter: null, submitters: [] })])
    await screen.findByRole('link', { name: /查看扫描 .* 的完整证据/ })
    expect(screen.getByText(/提交者：未知/)).toBeInTheDocument()
  })
})

// I3 (2026-07-29): `review_pending -> submitted` became legal in milestone F
// Task 11, so a skill awaiting review can ship a corrected version - and the
// earlier REVIEW verdict stays in the queue. Deciding it used to be accepted,
// signed, and then discarded by the lifecycle worker with no feedback at all.
describe('ReviewsPage superseded entries', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('offers no decision on a superseded entry', async () => {
    renderReviews([reviewScan({ superseded: true })])
    await screen.findByText('已失效')
    // The buttons are GONE, not merely disabled - the API refuses the request
    // (409) and the worker would drop the answer, so there is no action here
    // to leave lying around.
    expect(screen.queryByRole('button', { name: '通过' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '拒绝' })).not.toBeInTheDocument()
  })

  it('explains WHY it cannot be decided instead of hiding the entry', async () => {
    renderReviews([reviewScan({ superseded: true })])
    // Still listed: an item that silently vanishes teaches an approver
    // nothing about where their queue went.
    expect(await screen.findByText(/该 Skill 的生命周期已离开此条复核对应的内容/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /查看扫描 .* 的完整证据/ })).toBeInTheDocument()
  })

  it('leaves a live review fully decidable', async () => {
    renderReviews([reviewScan({ superseded: false })])
    expect(await screen.findByRole('button', { name: '通过' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '拒绝' })).toBeInTheDocument()
    expect(screen.queryByText('已失效')).not.toBeInTheDocument()
  })
})
