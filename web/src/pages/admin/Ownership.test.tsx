import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../../i18n/I18nContext'
import { ToastProvider } from '../../components/Toast'
import { AdminOwnershipPage } from './Ownership'
import type { UnownedSkill } from '../../api/types'

const { mockGet, mockPost } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPost: vi.fn() }))

vi.mock('../../api/client', () => {
  class ApiError extends Error {
    detail: string
    constructor(detail: string) {
      super(detail)
      this.detail = detail
    }
  }
  class SessionExpiredError extends ApiError {}
  return {
    api: { get: mockGet, post: mockPost },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

function unowned(overrides: Partial<UnownedSkill> = {}): UnownedSkill {
  return {
    skill_id: 'legacy-skill-1',
    source: 'clawhub',
    trust_tier: 'internal',
    state: 'published',
    genesis_actor: 'alice',
    created_at: '2026-01-01T00:00:00',
    ...overrides,
  }
}

function respondWith(skills: UnownedSkill[], total = skills.length) {
  mockGet.mockResolvedValue({ total, skills })
}

function renderPage() {
  render(
    <I18nProvider>
      <ToastProvider>
        <AdminOwnershipPage />
      </ToastProvider>
    </I18nProvider>,
  )
}

function ownerInput(): HTMLInputElement {
  return screen.getByPlaceholderText('登录身份') as HTMLInputElement
}

function reasonInput(): HTMLInputElement {
  // The reason field is the only labelled "原因" input on this page's form.
  return screen.getByLabelText('原因') as HTMLInputElement
}

function assignButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: /指派选中的/ }) as HTMLButtonElement
}

// No stored locale in this environment, so I18nProvider falls back to zh.
describe('AdminOwnershipPage', () => {
  beforeEach(() => {
    mockGet.mockReset()
    mockPost.mockReset()
  })

  it('asks for the unowned worklist with an explicit window', async () => {
    respondWith([unowned()])
    renderPage()
    await screen.findByText('legacy-skill-1')
    expect(mockGet.mock.calls[0][0]).toContain('/v1/inventory/ownership/unowned')
    expect(mockGet.mock.calls[0][0]).toContain('offset=0')
  })

  it('states the total, not just what fits on the page', async () => {
    // ~481 stranded rows is the case this page exists for. A page of 100 that
    // says nothing about the rest reads as "that is all of them".
    respondWith([unowned()], 481)
    renderPage()
    expect(await screen.findByText(/共 481 个无归属 Skill/)).toBeInTheDocument()
  })

  it('shows each skill_id next to its genesis submitter', async () => {
    respondWith([
      unowned({ skill_id: 'skill-a', genesis_actor: 'alice' }),
      unowned({ skill_id: 'skill-b', genesis_actor: 'bob' }),
    ])
    renderPage()
    const rowA = (await screen.findByText('skill-a')).closest('tr') as HTMLElement
    expect(within(rowA).getByText('alice')).toBeInTheDocument()
    const rowB = screen.getByText('skill-b').closest('tr') as HTMLElement
    expect(within(rowB).getByText('bob')).toBeInTheDocument()
  })

  it('reports a missing genesis actor as unknown rather than inventing one', async () => {
    respondWith([unowned({ genesis_actor: null })])
    renderPage()
    expect(await screen.findByText('无记录')).toBeInTheDocument()
  })

  it('says out loud that the genesis actor is evidence, not the decision', async () => {
    // The whole reason C1 refused to backfill `owner` from this column. If the
    // page ever stops saying it, the next person to look at 481 rows and one
    // suggestive column will do the backfill by hand.
    respondWith([unowned()])
    renderPage()
    expect(
      await screen.findByText(/不等于现在谁有权修改它。系统不会自动采用该值/),
    ).toBeInTheDocument()
  })

  it('offers no control that assigns genesis actors automatically', async () => {
    // The rejected backfill in console form. Selecting rows and typing the
    // identity is a deliberate act; a one-click "adopt every genesis actor"
    // would be the same migration wearing a button.
    respondWith([unowned()])
    renderPage()
    await screen.findByText('legacy-skill-1')
    for (const button of screen.getAllByRole('button')) {
      expect(button.textContent ?? '').not.toMatch(/创世/)
    }
  })

  it('renders the lifecycle state through the shared badge, not the raw wire value', async () => {
    // The bug c7e9bcd fixed in the inventory detail tile, reintroduced here:
    // this table used to render `s.state ?? '—'` raw, so a published skill
    // read "published" in English regardless of locale instead of "已发布".
    respondWith([unowned({ state: 'published' })])
    renderPage()
    const row = (await screen.findByText('legacy-skill-1')).closest('tr') as HTMLElement
    const badge = within(row).getByText('已发布')
    expect(badge.className).toContain('badge-pass')
    expect(within(row).queryByText('published')).toBeNull()
  })

  it('cannot assign until an owner and a reason are both typed', async () => {
    respondWith([unowned()])
    renderPage()
    const row = (await screen.findByText('legacy-skill-1')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('checkbox'))
    expect(assignButton()).toBeDisabled()
    fireEvent.change(ownerInput(), { target: { value: 'alice' } })
    expect(assignButton()).toBeDisabled()
    fireEvent.change(reasonInput(), { target: { value: 'verified with the team' } })
    expect(assignButton()).toBeEnabled()
  })

  it('cannot assign with nothing selected, however complete the form is', async () => {
    respondWith([unowned()])
    renderPage()
    await screen.findByText('legacy-skill-1')
    fireEvent.change(ownerInput(), { target: { value: 'alice' } })
    fireEvent.change(reasonInput(), { target: { value: 'r' } })
    expect(assignButton()).toBeDisabled()
  })

  it('selects every visible row at once and posts exactly those ids', async () => {
    // The bulk half: 481 rows is not a one-at-a-time form.
    respondWith([
      unowned({ skill_id: 'skill-a' }),
      unowned({ skill_id: 'skill-b' }),
      unowned({ skill_id: 'skill-c' }),
    ])
    mockPost.mockResolvedValue({ owner: 'alice', assigned: ['skill-a', 'skill-b', 'skill-c'], failed: [] })
    renderPage()
    await screen.findByText('skill-a')
    fireEvent.click(screen.getByLabelText('全选当前页'))
    fireEvent.change(ownerInput(), { target: { value: '  alice  ' } })
    fireEvent.change(reasonInput(), { target: { value: 'batch 1' } })
    fireEvent.click(assignButton())
    fireEvent.click(await screen.findByRole('button', { name: '确认' }))

    await waitFor(() => expect(mockPost).toHaveBeenCalled())
    expect(mockPost.mock.calls[0][0]).toBe('/v1/inventory/ownership/assign')
    const body = mockPost.mock.calls[0][1] as { owner: string; skill_ids: string[] }
    // Trimmed: the backend compares the stored owner to the login subject
    // verbatim, so a stray space is a permanent lockout that looks like success.
    expect(body.owner).toBe('alice')
    expect(body.skill_ids.sort()).toEqual(['skill-a', 'skill-b', 'skill-c'])
  })

  it('sends no expect_unowned flag - the bulk route can never transfer', async () => {
    // Assignment only. A mass revocation of other people's authority is not
    // expressible here, and the client must not imply otherwise.
    respondWith([unowned()])
    mockPost.mockResolvedValue({ owner: 'alice', assigned: ['legacy-skill-1'], failed: [] })
    renderPage()
    const row = (await screen.findByText('legacy-skill-1')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('checkbox'))
    fireEvent.change(ownerInput(), { target: { value: 'alice' } })
    fireEvent.change(reasonInput(), { target: { value: 'r' } })
    fireEvent.click(assignButton())
    fireEvent.click(await screen.findByRole('button', { name: '确认' }))

    await waitFor(() => expect(mockPost).toHaveBeenCalled())
    expect(mockPost.mock.calls[0][1]).not.toHaveProperty('expect_unowned')
  })

  it('confirms before assigning, naming the count and the identity', async () => {
    // A privilege change over N objects does not happen on a single click.
    respondWith([unowned()])
    renderPage()
    const row = (await screen.findByText('legacy-skill-1')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('checkbox'))
    fireEvent.change(ownerInput(), { target: { value: 'alice' } })
    fireEvent.change(reasonInput(), { target: { value: 'r' } })
    fireEvent.click(assignButton())
    expect(await screen.findByText(/将把 1 个 Skill 的归属人设为 alice/)).toBeInTheDocument()
    expect(mockPost).not.toHaveBeenCalled()
  })

  it('shows every row that was not assigned instead of rounding to success', async () => {
    // Partial success is the normal outcome of a stale worklist, and a toast
    // that said "done" would leave those rows silently unowned.
    respondWith([unowned({ skill_id: 'skill-a' }), unowned({ skill_id: 'skill-b' })])
    mockPost.mockResolvedValue({
      owner: 'alice',
      assigned: ['skill-a'],
      failed: [{ skill_id: 'skill-b', error: "skill 'skill-b' is already owned by 'bob'" }],
    })
    renderPage()
    await screen.findByText('skill-a')
    fireEvent.click(screen.getByLabelText('全选当前页'))
    fireEvent.change(ownerInput(), { target: { value: 'alice' } })
    fireEvent.change(reasonInput(), { target: { value: 'r' } })
    fireEvent.click(assignButton())
    fireEvent.click(await screen.findByRole('button', { name: '确认' }))

    expect(await screen.findByText(/is already owned by 'bob'/)).toBeInTheDocument()
    expect(screen.getByText(/成功 1 项，失败 1 项/)).toBeInTheDocument()
  })

  // 2026-07-29 residual triage. `skill.owner` is free text with no roster to
  // validate against, so the backend is right to shape-check only - but a typo
  // then fails SILENTLY: the write succeeds, the skills stay admin-only, and
  // nobody finds out until the real owner's next submission 403s.
  async function assignAs(owner: string, result: Record<string, unknown>) {
    respondWith([unowned()])
    mockPost.mockResolvedValue({ owner, assigned: ['legacy-skill-1'], failed: [], ...result })
    renderPage()
    const row = (await screen.findByText('legacy-skill-1')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('checkbox'))
    fireEvent.change(ownerInput(), { target: { value: owner } })
    fireEvent.change(reasonInput(), { target: { value: 'r' } })
    fireEvent.click(assignButton())
    fireEvent.click(await screen.findByRole('button', { name: '确认' }))
    await waitFor(() => expect(mockPost).toHaveBeenCalled())
  }

  it('warns when the assigned identity has never been seen, without calling it a failure', async () => {
    await assignAs('alicce', { owner_recognized: false })
    expect(await screen.findByText(/没有见过身份 alicce/)).toBeInTheDocument()
    // The assignment really happened. An advisory that reads as an error would
    // send the admin looking for rows that are not there.
    expect(screen.queryByText(/未能指派的项/)).toBeNull()
  })

  it('says so when the recognition check itself could not run', async () => {
    // Distinct from "not found": claiming an identity is unknown when nothing
    // actually looked would train admins to ignore the real warning.
    await assignAs('alice', { owner_recognized: null })
    expect(await screen.findByText(/未能核对身份 alice/)).toBeInTheDocument()
  })

  it('says nothing at all for a recognized identity', async () => {
    await assignAs('alice', { owner_recognized: true })
    await screen.findByText(/共 1 个无归属 Skill/)
    expect(screen.queryByText(/没有见过身份/)).toBeNull()
    expect(screen.queryByText(/未能核对身份/)).toBeNull()
  })
})
