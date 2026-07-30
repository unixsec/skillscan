import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n/I18nContext'
import { ToastProvider } from '../components/Toast'
import { ApiError } from '../api/client'
import { ScansPage } from './Scans'
import type { ScanSummary } from '../api/types'

const { mockGet, mockPostForm, mockUseSession } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPostForm: vi.fn(),
  mockUseSession: vi.fn(),
}))

vi.mock('../api/client', () => {
  // Mirrors the real signature (status, detail) - a mock that took only the
  // detail let a test construct an ApiError the app could never receive.
  class ApiError extends Error {
    status: number
    detail: string
    constructor(status: number, detail: string) {
      super(detail)
      this.status = status
      this.detail = detail
    }
  }
  class SessionExpiredError extends ApiError {}
  return {
    api: { get: mockGet, postForm: mockPostForm },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

// `hasAnyRole` stays real - it is the actual predicate the page uses to decide
// whether it may do the inventory lookup at all, and stubbing it would test
// the stub. Only the hook is replaced (App.test.tsx's pattern).
vi.mock('../auth/SessionContext', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/SessionContext')>()
  return { ...actual, useSession: mockUseSession }
})

function asRoles(...roles: string[]) {
  mockUseSession.mockReturnValue({
    session: { subject: 'carol', roles, tier: 'internal' },
    loading: false,
    refresh: () => {},
    logout: async () => {},
  })
}

const PAGE_SIZE = 50

// `state: 'decided'` on purpose: a terminal state means useApiData installs no
// poll timer, so these tests never race a background fetch.
function summary(index: number): ScanSummary {
  const id = String(index).padStart(8, '0')
  return {
    scan_id: `${id}-aaaa-bbbb-cccc-dddddddddddd`,
    state: 'decided',
    submitter: `submitter-${index}`,
    content_hash: String(index).padStart(64, 'f'),
    verdict: 'PASS',
    score: 90,
    is_safe: true,
    skill_id: `skill-${index}`,
    skill_name: `Skill ${index}`,
  }
}

function respondWith(count: number, firstIndex = 1) {
  mockGet.mockResolvedValue({
    items: Array.from({ length: count }, (_, i) => summary(firstIndex + i)),
  })
}

function renderScans() {
  render(
    <MemoryRouter>
      <I18nProvider>
        <ToastProvider>
          <ScansPage />
        </ToastProvider>
      </I18nProvider>
    </MemoryRouter>,
  )
}

function lastRequestedUrl(): string {
  return mockGet.mock.calls[mockGet.mock.calls.length - 1][0] as string
}

async function bodyRowCount(): Promise<number> {
  const table = await screen.findByRole('table')
  // -1 for the header row, which is inside the same table.
  return within(table).getAllByRole('row').length - 1
}

// No stored locale in this environment, so I18nProvider falls back to its
// default (zh) - the assertions below are against the Chinese strings.
describe('ScansPage pagination', () => {
  beforeEach(() => {
    mockGet.mockReset()
    // No session by default - the pagination tests predate the ownership
    // lookup and must keep exercising exactly the requests they did before.
    mockUseSession.mockReturnValue({
      session: null,
      loading: false,
      refresh: () => {},
      logout: async () => {},
    })
  })

  it('sends an explicit window instead of inheriting the backend default', async () => {
    // The bug: `/v1/scans` with no params against `limit = 50`, so scan 51
    // onwards simply did not exist as far as the console was concerned.
    respondWith(PAGE_SIZE)
    renderScans()
    await screen.findByText('Skill 1')
    expect(lastRequestedUrl()).toContain(`limit=${PAGE_SIZE + 1}`)
    expect(lastRequestedUrl()).toContain('offset=0')
  })

  it('asks for one row more than it shows, to learn whether a next page exists', async () => {
    // /v1/scans returns no total count, so the extra row IS the has-next probe.
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')
    expect(await bodyRowCount()).toBe(PAGE_SIZE)
    expect(screen.queryByText('Skill 51')).toBeNull()
  })

  it('offers a next page exactly when the probe row came back', async () => {
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')
    expect(screen.getByRole('button', { name: '下一页' })).toBeEnabled()
  })

  it('hides the pager when everything already fits on one page', async () => {
    respondWith(PAGE_SIZE)
    renderScans()
    await screen.findByText('Skill 1')
    expect(screen.queryByRole('button', { name: '下一页' })).toBeNull()
    expect(screen.queryByRole('button', { name: '上一页' })).toBeNull()
  })

  it('advances the offset by one page, not by the over-fetched row count', async () => {
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')

    respondWith(PAGE_SIZE + 1, PAGE_SIZE + 1)
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    // 50, not 51 - off-by-one here would skip a scan on every page turn.
    await waitFor(() => expect(lastRequestedUrl()).toContain(`offset=${PAGE_SIZE}`))
    expect(await screen.findByText('Skill 51')).toBeInTheDocument()
  })

  it('walks back to the previous offset', async () => {
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')

    respondWith(PAGE_SIZE + 1, PAGE_SIZE + 1)
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByText('Skill 51')

    respondWith(PAGE_SIZE + 1)
    fireEvent.click(screen.getByRole('button', { name: '上一页' }))
    await waitFor(() => expect(lastRequestedUrl()).toContain('offset=0'))
  })

  it('does not claim a total it was never told', async () => {
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')
    // "第 1 页", never "第 1 / 2 页" - the backend returns rows, not a count,
    // and an invented total is a lie the user cannot detect.
    expect(screen.getByText('第 1 页')).toBeInTheDocument()
    expect(screen.queryByText(/第 1 \/ \d+ 页/)).toBeNull()
  })

  it('stops offering a next page once a short page comes back', async () => {
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')

    respondWith(10, PAGE_SIZE + 1)
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByText('Skill 51')
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '上一页' })).toBeEnabled()
  })

  it('says the filters only see the current page', async () => {
    respondWith(PAGE_SIZE + 1)
    renderScans()
    await screen.findByText('Skill 1')
    // Otherwise "filter by BLOCK, see nothing" reads as "there are no blocked
    // scans" when it only ever meant "none on this page".
    expect(screen.getByText(/筛选仅作用于当前页的 50 条记录/)).toBeInTheDocument()
  })

  it('stays quiet about page scope when there is only one page', async () => {
    respondWith(3)
    renderScans()
    await screen.findByText('Skill 1')
    expect(screen.queryByText(/筛选仅作用于当前页/)).toBeNull()
  })
})

// 里程碑 F Task 16: the list carried only the scalar `ScanJob.submitter` - the
// FIRST submitter. Byte-identical submissions collapse onto one scan_job, so on
// a deduplicated scan that name is a STRANGER'S to everyone who submitted
// afterwards: the table showed them somebody else as the owner of their own
// scan, with the correct names only in the detail drawer one click away.
describe('ScansPage submitter attribution', () => {
  beforeEach(() => {
    mockGet.mockReset()
    asRoles('approver')
  })

  function respondWithOne(overrides: Partial<ScanSummary>) {
    mockGet.mockResolvedValue({ items: [{ ...summary(1), ...overrides }] })
  }

  it('shows every submitter of a deduplicated scan, not just the first', async () => {
    respondWithOne({ submitter: 'alice', submitters: ['alice', 'bob'] })
    renderScans()
    await screen.findByText('Skill 1')
    expect(screen.getByText('alice, bob')).toBeInTheDocument()
  })

  it('falls back to the legacy scalar when the list did not come back', async () => {
    // A backend that predates the field. The fallback never invents a name - it
    // just uses the one that WAS on record.
    respondWithOne({ submitter: 'carol', submitters: undefined })
    renderScans()
    await screen.findByText('Skill 1')
    // Scoped to the table: "carol" is also a filter-dropdown option, and the
    // assertion here is about the ROW.
    const table = await screen.findByRole('table')
    expect(within(table).getByText('carol')).toBeInTheDocument()
  })

  it('lets a co-submitter filter to a deduplicated scan they did not submit first', async () => {
    // The filter used to read `row.submitter`, so choosing "bob" hid the very
    // scan bob submitted whenever alice got there first - and this list is the
    // only route to it through the UI.
    respondWithOne({ submitter: 'alice', submitters: ['alice', 'bob'] })
    renderScans()
    await screen.findByText('Skill 1')
    const submitterFilter = screen.getByLabelText('提交者')
    expect(within(submitterFilter as HTMLSelectElement).getByText('bob')).toBeInTheDocument()
    fireEvent.change(submitterFilter, { target: { value: 'bob' } })
    expect(screen.getByText('alice, bob')).toBeInTheDocument()
  })
})

// 里程碑 F Task 15 step 4. `POST /v1/scans` takes `trust_tier` as a form
// field, but a RESUBMISSION of an already-registered skill_id is judged at the
// skill's RECORDED tier and the field is discarded (gateway/router.py, finding
// I2 - otherwise any submitter could re-judge a `public` skill as `internal`
// and downgrade a finding that had to block). The form went on offering the
// control regardless, so the user was picking a value nothing would ever read.
describe('ScansPage trust tier on a resubmission', () => {
  const KNOWN_SKILL = 'already-registered'

  function respondByPath(inventory: (skillId: string) => Promise<unknown>) {
    mockGet.mockImplementation((path: string) => {
      if (path.startsWith('/v1/inventory/')) {
        return inventory(decodeURIComponent(path.slice('/v1/inventory/'.length)))
      }
      return Promise.resolve({ items: [summary(1)] })
    })
  }

  const registeredAsPublic = (skillId: string) =>
    skillId === KNOWN_SKILL
      ? Promise.resolve({
          skill_id: skillId,
          source: 'console',
          trust_tier: 'public',
          state: 'published',
          owner: 'alice',
          versions: [],
          baseline: null,
        })
      : Promise.reject(new Error('skill not found'))

  beforeEach(() => {
    mockGet.mockReset()
    mockPostForm.mockReset()
    mockPostForm.mockResolvedValue({})
  })

  async function typeSkillId(value: string) {
    const input = screen.getByPlaceholderText('填写后登记进清单并跟踪生命周期')
    fireEvent.change(input, { target: { value } })
  }

  function tierSelect(): HTMLSelectElement {
    return screen.getByRole('combobox', { name: /信任层级/ }) as HTMLSelectElement
  }

  it('disables the tier control for a skill_id that is already registered', async () => {
    asRoles('approver')
    respondByPath(registeredAsPublic)
    renderScans()
    await screen.findByText('Skill 1')
    await typeSkillId(KNOWN_SKILL)
    await waitFor(() => expect(tierSelect()).toBeDisabled(), { timeout: 2000 })
    // Shows the tier that will ACTUALLY be used, not the one last picked.
    expect(tierSelect().value).toBe('public')
  })

  it('says why the control is disabled, naming the tier the verdict will use', async () => {
    asRoles('admin')
    respondByPath(registeredAsPublic)
    renderScans()
    await screen.findByText('Skill 1')
    await typeSkillId(KNOWN_SKILL)
    // Silently disabling a control is only half an improvement - "it does
    // nothing" has to be legible, with the value that replaces it. Matched on
    // the hint sentence, not on the bare tier label: `公开` also appears as an
    // <option> inside the very select under test, so a looser match would pass
    // with no hint on the page at all.
    expect(
      await screen.findByText(/记录的信任层级（公开）/, {}, { timeout: 2000 }),
    ).toBeInTheDocument()
  })

  it('leaves the control usable for a skill_id nobody has registered', async () => {
    asRoles('approver')
    respondByPath(registeredAsPublic)
    renderScans()
    await screen.findByText('Skill 1')
    await typeSkillId('brand-new-skill')
    // A first registration DOES honour the submitted tier, so disabling it
    // here would break the only case where the control matters.
    await waitFor(() => expect(tierSelect()).toBeEnabled(), { timeout: 2000 })
    expect(screen.getByText(/仅在该 Skill ID 首次登记时生效/)).toBeInTheDocument()
  })

  it('re-enables the control when a known skill_id is edited into an unknown one', async () => {
    // The stale-state trap: leaving the previous lookup's answer on screen
    // would keep the control disabled - and showing the wrong tier - for a
    // brand-new skill.
    asRoles('approver')
    respondByPath(registeredAsPublic)
    renderScans()
    await screen.findByText('Skill 1')
    await typeSkillId(KNOWN_SKILL)
    await waitFor(() => expect(tierSelect()).toBeDisabled(), { timeout: 2000 })
    await typeSkillId('something-else')
    await waitFor(() => expect(tierSelect()).toBeEnabled(), { timeout: 2000 })
  })

  it('never issues the lookup for a role that may not read inventory', async () => {
    // `GET /v1/inventory/{skill_id}` is approver/auditor/admin, and it is
    // deliberately NOT widened for this: a lookup any submitter could call
    // turns "does this skill_id exist, at what tier" into a cheap enumeration
    // probe. A submitter gets the standing hint instead, which is true in
    // either case.
    asRoles('submitter')
    respondByPath(registeredAsPublic)
    renderScans()
    await screen.findByText('Skill 1')
    await typeSkillId(KNOWN_SKILL)
    await waitFor(
      () => expect(screen.getByText(/仅在该 Skill ID 首次登记时生效/)).toBeInTheDocument(),
      { timeout: 2000 },
    )
    expect(
      mockGet.mock.calls.filter((c) => String(c[0]).startsWith('/v1/inventory/')),
    ).toHaveLength(0)
    expect(tierSelect()).toBeEnabled()
  })

  it('submits the recorded tier rather than a contradicting form value', async () => {
    asRoles('approver')
    respondByPath(registeredAsPublic)
    renderScans()
    await screen.findByText('Skill 1')
    await typeSkillId(KNOWN_SKILL)
    await waitFor(() => expect(tierSelect()).toBeDisabled(), { timeout: 2000 })

    const file = new File(['x'], 'pkg.tar', { type: 'application/x-tar' })
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(fileInput, { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: '提交扫描' }))

    await waitFor(() => expect(mockPostForm).toHaveBeenCalled())
    const form = mockPostForm.mock.calls[0][1] as FormData
    expect(form.get('skill_id')).toBe(KNOWN_SKILL)
    // `internal` is the component's default and would be a claim the client
    // knows to be untrue.
    expect(form.get('trust_tier')).toBe('public')
  })
})

// 2026-07-30. Two defects that had been in this form since it was written:
// the file picker offered every file on disk (`FileField` has always supported
// `accept`, and admin/Intel.tsx uses it), and an archive rejection surfaced as
// the RAW English backend detail - `reasons.ts` covers VerdictRow.reasons, not
// ingest 400s, so nothing translated it.
describe('ScansPage package upload affordances', () => {
  beforeEach(() => {
    mockGet.mockReset()
    mockPostForm.mockReset()
    respondWith(1)
    asRoles('submitter')
  })

  function fileInput(): HTMLInputElement {
    return document.querySelector('input[type="file"]') as HTMLInputElement
  }

  it('offers the two container formats the endpoint accepts', async () => {
    renderScans()
    await screen.findByText('Skill 1')
    const accept = fileInput().getAttribute('accept') ?? ''
    expect(accept).toContain('.tar')
    expect(accept).toContain('.zip')
  })

  it('says the package may be a zip, not tar only', async () => {
    renderScans()
    await screen.findByText('Skill 1')
    // The label said "（tar）" while the backend refused every zip - the label
    // was accurate and the product was wrong; both are fixed together.
    expect(screen.getByText(/tar 或 zip/)).toBeInTheDocument()
  })

  async function submitAndFail(detail: string) {
    mockPostForm.mockRejectedValue(new ApiError(400, detail))
    renderScans()
    await screen.findByText('Skill 1')
    const file = new File(['x'], 'pkg.zip', { type: 'application/zip' })
    fireEvent.change(fileInput(), { target: { files: [file] } })
    fireEvent.click(screen.getByRole('button', { name: '提交扫描' }))
  }

  it('translates an archive rejection instead of echoing the backend English', async () => {
    await submitAndFail('invalid package archive: not a valid tar archive: bad header')
    expect(await screen.findByText(/不是可识别的软件包格式/)).toBeInTheDocument()
    expect(screen.queryByText(/not a valid tar archive/)).toBeNull()
  })

  it('translates a decompression-bomb refusal', async () => {
    await submitAndFail(
      'invalid package archive: compression ratio 1015.0 exceeds max 100 (decompression-bomb defense)',
    )
    expect(await screen.findByText(/解压炸弹/)).toBeInTheDocument()
  })

  it('still shows a non-ingest failure verbatim', async () => {
    // A 409 is already a precise sentence; replacing it with a guess would be a
    // regression, so the translator only ever touches the ingest prefix.
    const detail = "this content is already registered to skill 'other-skill'"
    await submitAndFail(detail)
    expect(await screen.findByText(detail)).toBeInTheDocument()
  })
})
