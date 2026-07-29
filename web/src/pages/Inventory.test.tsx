import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../i18n/I18nContext'
import { ToastProvider } from '../components/Toast'
import { InventoryDetailContent, InventoryListPage, RETIRE_ELIGIBLE_STATES } from './Inventory'
import type { InventoryDetail, InventorySkill, Session } from '../api/types'
// Ambient types for the three node: imports above come from the sibling
// node-fs-shim.d.ts - tsconfig.app.json's "include": ["src"] picks it up
// automatically (a .d.ts with no top-level import/export needs no explicit
// import to apply); see that file's own comment for why this couldn't just
// be tsconfig.app.json's "types": ["node"].

const { mockGet, mockPost, mockUseSession } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockUseSession: vi.fn(),
}))

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
    api: { get: mockGet, post: mockPost },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

// Layout.tsx also pulls `hasAnyRole` from this module - importOriginal keeps
// that (and everything else) real, so only the one hook the admin-action
// tests below actually drive gets replaced (same pattern as App.test.tsx).
vi.mock('../auth/SessionContext', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/SessionContext')>()
  return { ...actual, useSession: mockUseSession }
})

function asAdmin() {
  const session: Session = { subject: 'admin-alice', roles: ['admin'], tier: 'internal' }
  mockUseSession.mockReturnValue({ session, loading: false, refresh: () => {}, logout: async () => {} })
}

function asNonAdmin() {
  const session: Session = { subject: 'carol', roles: ['approver'], tier: 'internal' }
  mockUseSession.mockReturnValue({ session, loading: false, refresh: () => {}, logout: async () => {} })
}

function skill(overrides: Partial<InventorySkill> = {}): InventorySkill {
  return {
    skill_id: 'demo-skill',
    source: 'console',
    trust_tier: 'internal',
    state: 'blocked',
    owner: 'alice',
    ...overrides,
  }
}

function renderList(skills: InventorySkill[]) {
  mockGet.mockResolvedValue({ skills })
  render(
    <MemoryRouter>
      <I18nProvider>
        <InventoryListPage />
      </I18nProvider>
    </MemoryRouter>,
  )
}

function renderDetail(overrides: Partial<InventoryDetail> = {}) {
  mockGet.mockResolvedValue({
    skill_id: 'demo-skill',
    source: 'console',
    trust_tier: 'internal',
    state: 'blocked',
    owner: 'alice',
    versions: [],
    baseline: null,
    ...overrides,
  } satisfies InventoryDetail)
  return render(
    <I18nProvider>
      <ToastProvider>
        <InventoryDetailContent skillId="demo-skill" />
      </ToastProvider>
    </I18nProvider>,
  )
}

// Scoped to the table on purpose: TableFilterBar renders the same lifecycle
// labels inside its filter <select>, so an unscoped getByText matches both the
// dropdown option and the row and proves nothing about either.
async function stateCell(label: string) {
  const table = await screen.findByRole('table')
  return within(table).getByText(label)
}

// No stored locale in this environment, so I18nProvider falls back to its
// default (zh) - the assertions below are against the Chinese strings.
describe('Inventory lifecycle state rendering', () => {
  beforeEach(() => {
    mockGet.mockReset()
    // Default to signed-out - matches the pre-mock behaviour of these tests,
    // which never wrapped a SessionProvider and so saw SessionContext's
    // `session: null` default. Tests that need an admin call asAdmin().
    mockUseSession.mockReturnValue({ session: null, loading: false, refresh: () => {}, logout: async () => {} })
  })

  it('renders `blocked` as its own translated state', async () => {
    renderList([skill({ state: 'blocked' })])
    expect(await stateCell('已拦截')).toBeInTheDocument()
  })

  it('does not let a blocked skill look like one still being scanned', async () => {
    // The pre-Task-1 failure mode: a BLOCKed skill sat in `scanning` forever
    // and was indistinguishable from an in-flight one. Both the wording and
    // the colour class have to separate them now.
    renderList([
      skill({ skill_id: 'blocked-one', state: 'blocked' }),
      skill({ skill_id: 'scanning-one', state: 'scanning' }),
    ])
    const blocked = await stateCell('已拦截')
    const scanning = await stateCell('扫描中')
    expect(blocked.className).toContain('badge-block')
    expect(scanning.className).not.toContain('badge-block')
    expect(scanning.textContent).not.toBe(blocked.textContent)
  })

  it('marks a published skill as passing and a quarantined one as blocking', async () => {
    renderList([
      skill({ skill_id: 'a', state: 'published' }),
      skill({ skill_id: 'b', state: 'quarantined' }),
    ])
    expect((await stateCell('已发布')).className).toContain('badge-pass')
    expect((await stateCell('已隔离')).className).toContain('badge-block')
  })

  it('echoes an unknown lifecycle state instead of rendering a translation key', async () => {
    renderList([skill({ state: 'some_future_state' })])
    expect(await stateCell('some_future_state')).toBeInTheDocument()
    expect(screen.queryByText('lifecycle.some_future_state')).toBeNull()
  })

  it('shows an em dash for a skill that never entered the state machine', async () => {
    renderList([skill({ state: null })])
    expect(await stateCell('—')).toBeInTheDocument()
  })

  it('translates the state on the detail view too, instead of showing the wire value', async () => {
    // This tile used to render `data.state` raw, so the same skill read
    // "blocked" here and "已拦截" in the list one click away.
    renderDetail({ state: 'blocked' })
    expect(await screen.findByText('已拦截')).toBeInTheDocument()
    expect(screen.queryByText('blocked')).toBeNull()
  })
})

// 里程碑 F Task 15: `skill.owner` decides who may submit a new version at all.
// C1 made `owner IS NULL` fail closed - admin only - which stranded every
// skill registered before the column existed (~481 on the deployed VM). These
// cover the console half of the recovery path.
describe('Inventory ownership', () => {
  beforeEach(() => {
    mockGet.mockReset()
    mockPost.mockReset()
    mockPost.mockResolvedValue({})
    mockUseSession.mockReturnValue({ session: null, loading: false, refresh: () => {}, logout: async () => {} })
  })

  it('names the owner rather than leaving the field invisible', async () => {
    renderDetail({ owner: 'alice' })
    expect(await screen.findByText('alice')).toBeInTheDocument()
  })

  it('spells out an absent owner and why it matters', async () => {
    // Without this, the 403 an unowned skill produces on submit looks like a
    // bug instead of a state with a name and a fix.
    renderDetail({ owner: null })
    expect(await screen.findByText('无归属记录')).toBeInTheDocument()
    expect(screen.getByText(/只有 admin 能为它提交新版本/)).toBeInTheDocument()
  })

  it('offers no ownership controls to a non-admin', async () => {
    // Step 3, decided NO: self-service claiming of an unowned asset is
    // first-come-first-served as an authorization model. The backend refuses
    // it too - this only keeps the console from implying otherwise.
    asNonAdmin()
    renderDetail({ owner: null })
    await screen.findByText('无归属记录')
    expect(screen.queryByRole('button', { name: '指派归属人' })).toBeNull()
    expect(screen.queryByRole('button', { name: '转移归属' })).toBeNull()
  })

  it('offers Assign for an unowned skill and Transfer for an owned one', async () => {
    asAdmin()
    renderDetail({ owner: null })
    expect(await screen.findByRole('button', { name: '指派归属人' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '转移归属' })).toBeNull()
  })

  it('calls a transfer a transfer, and names who loses the skill', async () => {
    asAdmin()
    renderDetail({ owner: 'alice' })
    expect(await screen.findByRole('button', { name: '转移归属' })).toBeInTheDocument()
    expect(screen.getByText(/当前归属人为 alice/)).toBeInTheDocument()
  })

  async function fillAndSubmitOwner(owner: string, buttonName: string) {
    fireEvent.change(screen.getByPlaceholderText('登录身份'), { target: { value: owner } })
    const reasonInputs = screen.getAllByLabelText('原因')
    fireEvent.change(reasonInputs[reasonInputs.length - 1], { target: { value: 'because' } })
    fireEvent.click(screen.getByRole('button', { name: buttonName }))
    fireEvent.click(await screen.findByRole('button', { name: '确认' }))
  }

  it('sends expect_unowned true when assigning an unowned skill', async () => {
    // The compare-and-set guard. A row that acquired an owner since this
    // drawer opened must 409, not be silently overwritten.
    asAdmin()
    renderDetail({ owner: null })
    await screen.findByRole('button', { name: '指派归属人' })
    await fillAndSubmitOwner('alice', '指派归属人')
    await waitFor(() => expect(mockPost).toHaveBeenCalled())
    expect(mockPost.mock.calls[0][0]).toBe('/v1/inventory/demo-skill/owner')
    expect(mockPost.mock.calls[0][1]).toMatchObject({ owner: 'alice', expect_unowned: true })
  })

  it('sends expect_unowned false only for a real transfer', async () => {
    asAdmin()
    renderDetail({ owner: 'alice' })
    await screen.findByRole('button', { name: '转移归属' })
    await fillAndSubmitOwner('bob', '转移归属')
    await waitFor(() => expect(mockPost).toHaveBeenCalled())
    expect(mockPost.mock.calls[0][1]).toMatchObject({ owner: 'bob', expect_unowned: false })
  })

  it('will not submit an owner or a reason left blank', async () => {
    asAdmin()
    renderDetail({ owner: null })
    const button = await screen.findByRole('button', { name: '指派归属人' })
    expect(button).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText('登录身份'), { target: { value: '   ' } })
    expect(button).toBeDisabled()
  })
})

// The admin action buttons are gated on `data.state` to match exactly what
// the backend's VALID_TRANSITIONS (lifecycle.py) accepts as a SOURCE state:
// quarantine only from `published`, restore only from `quarantined`, retire
// from RETIRE_ELIGIBLE_STATES (see Inventory.tsx). Before this, all three
// buttons rendered unconditionally for any admin viewing any state, so e.g.
// a quarantined skill offered a second "Quarantine" and a `submitted` or
// already-`retired` skill offered a "Retire" - none of which could do
// anything but 409.
describe('Inventory admin action gating (db0983c restore wiring)', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('a non-admin sees no lifecycle action buttons at all', async () => {
    asNonAdmin()
    renderDetail({ state: 'published' })
    await screen.findByText('已发布')
    expect(screen.queryByRole('button', { name: '隔离' })).toBeNull()
    expect(screen.queryByRole('button', { name: '恢复' })).toBeNull()
    expect(screen.queryByRole('button', { name: '退役' })).toBeNull()
  })

  it('a published skill offers Quarantine and Retire, not Restore', async () => {
    asAdmin()
    renderDetail({ state: 'published' })
    await screen.findByText('已发布')
    expect(screen.getByRole('button', { name: '隔离' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '退役' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '恢复' })).toBeNull()
  })

  it('a quarantined skill offers Restore and Retire, not a second Quarantine, plus its hint', async () => {
    asAdmin()
    renderDetail({ state: 'quarantined' })
    await screen.findByText('已隔离')
    expect(screen.getByRole('button', { name: '恢复' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '退役' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '隔离' })).toBeNull()
    expect(screen.getByText('仅对已隔离的 Skill 可用。隔离期间无法提交新版本，须先由 admin 恢复为已发布。')).toBeInTheDocument()
  })

  it('opens the restore confirmation with the restore-specific title', async () => {
    asAdmin()
    renderDetail({ state: 'quarantined' })
    const restoreButton = await screen.findByRole('button', { name: '恢复' })
    fireEvent.click(restoreButton)
    expect(await screen.findByText('确认恢复该 Skill？')).toBeInTheDocument()
  })

  it('hides Retire for `submitted` (only legal edge is -> scanning)', async () => {
    asAdmin()
    renderDetail({ state: 'submitted' })
    await screen.findByText('已提交')
    expect(screen.queryByRole('button', { name: '退役' })).toBeNull()
  })

  it('hides Retire for `retired` itself (terminal, no outbound edges)', async () => {
    asAdmin()
    renderDetail({ state: 'retired' })
    await screen.findByText('已退役')
    expect(screen.queryByRole('button', { name: '退役' })).toBeNull()
  })

  it('offers Retire for every other state (scanning/review_pending/published/quarantined/blocked)', async () => {
    for (const state of ['scanning', 'review_pending', 'published', 'quarantined', 'blocked']) {
      asAdmin()
      const { unmount } = renderDetail({ state })
      expect(await screen.findByRole('button', { name: '退役' })).toBeInTheDocument()
      unmount()
    }
  })
})

// SECURITY/UX: RETIRE_ELIGIBLE_STATES in Inventory.tsx is a hand-written
// TypeScript mirror of a Python dict (VALID_TRANSITIONS in
// apps/monolith/modules/inventory/lifecycle.py) - two frontend tests above
// can only prove the mirror renders self-consistently, never that it still
// matches the backend. This test reads the REAL lifecycle.py source text at
// test time and re-derives "which states may transition to retired" from it
// directly, so a future edit to VALID_TRANSITIONS that isn't mirrored into
// RETIRE_ELIGIBLE_STATES fails here instead of shipping a console button
// that always 409s - the same "new state/edge added, derived registry not
// updated" defect shape milestone D hit five times.
describe("RETIRE_ELIGIBLE_STATES is pinned to lifecycle.py's VALID_TRANSITIONS", () => {
  it('matches every state whose VALID_TRANSITIONS target set contains "retired"', () => {
    const lifecyclePath = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../../apps/monolith/modules/inventory/lifecycle.py',
    )
    const source = readFileSync(lifecyclePath, 'utf-8')

    const dictMatch = source.match(/VALID_TRANSITIONS: dict\[str, frozenset\[str]] = \{([\s\S]*?)\n\}\n/)
    if (!dictMatch) {
      throw new Error(
        'could not find VALID_TRANSITIONS in lifecycle.py - its declaration shape changed; ' +
          'update this regex (and re-check RETIRE_ELIGIBLE_STATES by hand) rather than deleting the test',
      )
    }
    const dictBody = dictMatch[1]

    const entryPattern = /"(\w+)":\s*frozenset\((?:\{([^}]*)\})?\)/g
    const statesSeen: string[] = []
    const retireEligibleFromSource = new Set<string>()
    for (const [, sourceState, targets] of dictBody.matchAll(entryPattern)) {
      statesSeen.push(sourceState)
      if (targets?.includes('"retired"')) retireEligibleFromSource.add(sourceState)
    }

    // Sanity floor: if the regex silently matched nothing (e.g. the file's
    // formatting changed) every assertion below would trivially "pass" on
    // two empty sets. Known state count today is 7 (submitted, scanning,
    // review_pending, published, quarantined, blocked, retired).
    expect(statesSeen.length).toBeGreaterThanOrEqual(7)

    expect([...retireEligibleFromSource].sort()).toEqual([...RETIRE_ELIGIBLE_STATES].sort())
  })
})
