import { act, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../api/client'
import { I18nProvider } from '../i18n/I18nContext'
import { ScanDetailContent, scanTrifectaSignals, submitterTierDivergence } from './ScanDetail'
import type { Finding, ScanDetail } from '../api/types'

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }))

// useApiData imports ApiError/SessionExpiredError from the same module, so the
// mock has to stand in for the whole client surface, not just `api`.
vi.mock('../api/client', () => {
  // Same constructor signature as the real one (client.ts): TypeScript checks
  // call sites against the REAL module's types, so a stand-in that took fewer
  // arguments would only be caught by tsc, and only once someone constructed
  // one in a test.
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
    api: { get: mockGet },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

// The localStorage stub I18nProvider needs, and RTL's afterEach(cleanup), both
// live in src/test/setup.ts now - see the comments there for why this
// environment needs either.

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    rule_id: 'INS-01',
    test_item_id: 'T-1',
    category: 'instruction',
    title: 'prompt injection',
    severity: 4,
    confidence: 0.7,
    source_engine: 'inhouse-instruction',
    source_capability: 'instruction',
    trifecta_signals: [],
    file_path: 'SKILL.md',
    start_line: 3,
    snippet_hash: 'abc',
    evidence_redacted: '[REDACTED]',
    ...overrides,
  }
}

// `state: 'decided'` on purpose: a terminal state means useApiData installs no
// poll timer, so these tests never race a background fetch.
function scan(overrides: Partial<ScanDetail> = {}): ScanDetail {
  return {
    scan_id: 'scan-1',
    state: 'decided',
    submitter: 'alice',
    verdict: 'BLOCK',
    severity: 4,
    score: 12,
    is_safe: false,
    findings: [finding()],
    provenance: [['inhouse-instruction', '1.0.0']],
    required_ok: true,
    hard_gate_hits: [],
    reasons: ['severity_all=CRITICAL'],
    trust_tier: 'public',
    judged_at_tier: 'public',
    // 里程碑 F Task 14: the ordinary case - the viewer asked for the tier the
    // verdict was reached at, so nothing is flagged. `tier_direction` is
    // server-computed and null whenever the two agree.
    tier_direction: null,
    submitters: ['alice'],
    source: ['console'],
    submitter_sources: [{ submitter: 'alice', source: 'console', requested_trust_tier: 'public' }],
    ...overrides,
  }
}

function renderScan(overrides: Partial<ScanDetail> = {}) {
  mockGet.mockResolvedValue(scan(overrides))
  render(
    <I18nProvider>
      <ScanDetailContent scanId="scan-1" />
    </I18nProvider>,
  )
}

// Waits for the fetched render (findings heading is always present once data
// has arrived), so a "renders nothing" assertion can't pass merely because the
// page is still loading.
async function waitForLoaded() {
  return screen.findByText(/发现明细/)
}

describe('scanTrifectaSignals', () => {
  it('unions the per-finding signals into one sorted, deduplicated scan-level set', () => {
    expect(
      scanTrifectaSignals([
        finding({ trifecta_signals: ['untrusted_input', 'external_egress'] }),
        finding({ trifecta_signals: ['untrusted_input', 'private_data_access'] }),
      ]),
    ).toEqual(['external_egress', 'private_data_access', 'untrusted_input'])
  })

  it('is empty when no finding carries a signal', () => {
    expect(scanTrifectaSignals([finding(), finding()])).toEqual([])
    expect(scanTrifectaSignals([])).toEqual([])
  })

  it('tolerates a finding row that predates the field', () => {
    const legacy = { ...finding(), trifecta_signals: undefined } as unknown as Finding
    expect(scanTrifectaSignals([legacy, finding({ trifecta_signals: ['external_egress'] })])).toEqual(
      ['external_egress'],
    )
  })
})

// 里程碑 F review finding 5: the per-submitter badge decided "this diverges"
// with a bare `!==` on the tier NAMES, while the headline three lines above
// used the server's policy-derived `tier_direction` for the same question.
describe('submitterTierDivergence', () => {
  it('reports nothing for the tier the verdict was actually reached at', () => {
    expect(
      submitterTierDivergence(
        { trust_tier: 'public', judged_at_tier: 'internal', tier_direction: 'looser' },
        'internal',
      ),
    ).toBeNull()
  })

  it('reports nothing when the policy blocks both tiers at the same threshold', () => {
    // The case the name comparison got wrong: `partner` and `internal` are
    // different strings that policies/gate/v1.yaml treats identically, so this
    // verdict means exactly the same thing for this submitter as for everyone
    // else. The headline says so in words; flagging it here contradicted it.
    expect(
      submitterTierDivergence(
        { trust_tier: 'partner', judged_at_tier: 'internal', tier_direction: 'equivalent' },
        'partner',
      ),
    ).toBe('equivalent')
  })

  it('passes the server’s direction through for a real divergence', () => {
    expect(
      submitterTierDivergence(
        { trust_tier: 'public', judged_at_tier: 'internal', tier_direction: 'looser' },
        'public',
      ),
    ).toBe('looser')
    expect(
      submitterTierDivergence(
        { trust_tier: 'internal', judged_at_tier: 'public', tier_direction: 'stricter' },
        'internal',
      ),
    ).toBe('stricter')
  })

  it('makes no claim about a tier the server never compared', () => {
    // bob asked for something neither the viewer nor the judged tier is, so
    // there is no server answer covering it. Reported as a divergence with no
    // direction attached - never guessed at from the order of the tier names,
    // which is not what determines strictness (gate.policy.tier_direction).
    expect(
      submitterTierDivergence(
        { trust_tier: 'internal', judged_at_tier: 'internal', tier_direction: null },
        'public',
      ),
    ).toBe('unknown')
  })

  it('does not swallow a divergence the server could not classify', () => {
    // `tier_direction: null` on names that DIFFER means "no comparison was
    // possible" (a tier the policy does not define), not "no divergence".
    expect(
      submitterTierDivergence(
        { trust_tier: 'not-a-tier', judged_at_tier: 'internal', tier_direction: null },
        'not-a-tier',
      ),
    ).toBe('unknown')
  })
})

describe('ScanDetail evidence rendering', () => {
  // No stored locale in this environment, so I18nProvider falls back to its
  // default (zh) - the assertions below are against the Chinese strings.
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('shows each finding’s confidence in its own column', async () => {
    renderScan({ findings: [finding({ confidence: 0.7 })] })
    await waitForLoaded()
    expect(screen.getByText('置信度')).toBeInTheDocument()
    // Two decimals, not a rounded percentage - the policy threshold it is
    // compared against lives at this precision.
    expect(screen.getByText('0.70')).toBeInTheDocument()
  })

  it('renders no signals block at all when there is nothing to report', async () => {
    renderScan({ hard_gate_hits: [], findings: [finding({ trifecta_signals: [] })] })
    await waitForLoaded()
    expect(screen.queryByText('扫描级信号')).toBeNull()
    expect(screen.queryByText(/硬门禁命中/)).toBeNull()
    expect(screen.queryByText(/致命三元组信号/)).toBeNull()
  })

  it('lists hard-gate hits when the scan has them', async () => {
    // Rule ids the findings table does not also contain, so a hit is proven to
    // come from the scan-level block rather than from a findings row.
    renderScan({ hard_gate_hits: ['SUPPLY-02', 'NET-07'] })
    await waitForLoaded()
    expect(screen.getByText('扫描级信号')).toBeInTheDocument()
    expect(screen.getByText('SUPPLY-02')).toBeInTheDocument()
    expect(screen.getByText('NET-07')).toBeInTheDocument()
  })

  it('lists the scan-level trifecta signals, translated', async () => {
    renderScan({
      findings: [
        finding({ trifecta_signals: ['private_data_access'] }),
        finding({ trifecta_signals: ['external_egress'] }),
      ],
    })
    await waitForLoaded()
    expect(screen.getByText('私密数据访问')).toBeInTheDocument()
    expect(screen.getByText('对外传输')).toBeInTheDocument()
  })

  it('echoes an unknown trifecta signal instead of rendering a translation key', async () => {
    renderScan({ findings: [finding({ trifecta_signals: ['some_future_signal'] })] })
    await waitForLoaded()
    expect(screen.getByText('some_future_signal')).toBeInTheDocument()
    expect(screen.queryByText('trifecta.some_future_signal')).toBeNull()
  })

  it('shows both tiers side by side without a warning when they agree', async () => {
    renderScan({ trust_tier: 'public', judged_at_tier: 'public', tier_direction: null })
    await waitForLoaded()
    expect(screen.getByText(/本次请求的信任层级/)).toBeInTheDocument()
    expect(screen.queryByText(/更宽松/)).toBeNull()
    expect(screen.queryByText(/更严格/)).toBeNull()
  })

  // 里程碑 F Task 14. Until this task `trust_tier` and `judged_at_tier` were one
  // backend column read twice, so this branch was unreachable against real data
  // no matter what a fixture said. `trust_tier` is now the tier THIS viewer
  // asked for and `judged_at_tier` the tier the verdict was actually reached at.
  it('warns loudly when the verdict was judged at a MORE PERMISSIVE tier than requested', async () => {
    // The dangerous direction, and the reason the feature exists: `public` is
    // the strictest tier (blocks at HIGH), `internal` the most permissive
    // (blocks only at CRITICAL). Asking for `public` and being handed an
    // `internal` verdict means a finding that should have blocked can read PASS.
    // The direction is the SERVER's call (policies/gate/v1.yaml's thresholds),
    // never re-derived here from the tier names.
    renderScan({ trust_tier: 'public', judged_at_tier: 'internal', tier_direction: 'looser' })
    await waitForLoaded()
    const line = screen.getByText(/更宽松/)
    expect(line).toBeInTheDocument()
    // Not the same grey as the agreeing case: the line switches to the error
    // style, and the two tier badges stop matching each other.
    expect(line).toHaveClass('error')
    expect(screen.getByText('公开')).toHaveClass('badge-review')
    expect(screen.getByText('内部')).toHaveClass('badge-block')
  })

  it('states the safe direction too, without dressing it up as a warning', async () => {
    // Requested `internal`, judged at `public`: over-blocking is possible but
    // nothing slipped through. Reported, because an unexplained BLOCK is its own
    // failure - but NOT in the error style, or the styling stops meaning
    // anything on the case that actually matters.
    renderScan({ trust_tier: 'internal', judged_at_tier: 'public', tier_direction: 'stricter' })
    await waitForLoaded()
    const line = screen.getByText(/更严格/)
    expect(line).toBeInTheDocument()
    expect(line).not.toHaveClass('error')
    expect(screen.getByText('公开')).not.toHaveClass('badge-block')
  })

  it('says a name-only difference changes nothing when the policy treats both alike', async () => {
    renderScan({ trust_tier: 'partner', judged_at_tier: 'internal', tier_direction: 'equivalent' })
    await waitForLoaded()
    const line = screen.getByText(/相同的拦截阈值/)
    expect(line).toBeInTheDocument()
    expect(line).not.toHaveClass('error')
  })

  it('renders no tier line when the scan records no tier at all', async () => {
    renderScan({ trust_tier: null, judged_at_tier: null, tier_direction: null })
    await waitForLoaded()
    expect(screen.queryByText(/本次请求的信任层级/)).toBeNull()
  })

  it('answers "is this safe" in plain language, and admits when it does not know', async () => {
    renderScan({ is_safe: false })
    await waitForLoaded()
    expect(screen.getByText('不安全')).toBeInTheDocument()
  })

  // 里程碑 F review finding 1: a failed background poll used to go into
  // `error`, which DataState renders INSTEAD of the page - so a fully rendered,
  // still-running scan blanked out to one line of red text, and (because the
  // error was only ever cleared on the initial load) never came back.
  it('keeps the whole scan on screen when a background refresh fails', async () => {
    vi.useFakeTimers()
    try {
      mockGet
        .mockResolvedValueOnce(scan({ state: 'running' }))
        .mockRejectedValueOnce(new ApiError(503, 'upstream unavailable'))
        .mockResolvedValue(scan({ state: 'running' }))
      render(
        <I18nProvider>
          <ScanDetailContent scanId="scan-1" />
        </I18nProvider>,
      )
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0)
      })
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000) // first poll -> 503
      })

      expect(screen.getByText(/自动刷新失败/)).toBeInTheDocument()
      // Still the scan, not an error page: the data is the last real answer the
      // server gave and is perfectly renderable.
      expect(screen.getByText(/发现明细/)).toBeInTheDocument()
      expect(screen.queryByText(/^错误：/)).toBeNull()

      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000) // next poll succeeds
      })
      expect(screen.queryByText(/自动刷新失败/)).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('shows the humanised verdict reason, not the raw gate code', async () => {
    renderScan({ reasons: ['severity_all=CRITICAL'] })
    await waitForLoaded()
    expect(screen.getByText('全部发现综合严重级别：严重')).toBeInTheDocument()
    expect(screen.queryByText('severity_all=CRITICAL')).toBeNull()
  })
})

describe('ScanDetail submitter attribution', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('lists every submitter of a deduplicated scan, not just the first', async () => {
    // `submitter` is ScanJob's own column - the FIRST person to submit this
    // content. Showing only that name told bob his own scan belonged to alice.
    renderScan({
      submitter: 'alice',
      submitters: ['alice', 'bob'],
      source: ['console', 'marketplace'],
      submitter_sources: [
        { submitter: 'alice', source: 'console', requested_trust_tier: null },
        { submitter: 'bob', source: 'marketplace', requested_trust_tier: null },
      ],
    })
    await waitForLoaded()
    expect(screen.getByText(/alice/)).toBeInTheDocument()
    expect(screen.getByText(/bob/)).toBeInTheDocument()
  })

  it('names the channel each submitter came through', async () => {
    renderScan({
      submitter_sources: [
        { submitter: 'alice', source: 'console', requested_trust_tier: null },
        { submitter: 'bob', source: 'marketplace', requested_trust_tier: null },
      ],
    })
    await waitForLoaded()
    expect(screen.getByText(/alice · 控制台/)).toBeInTheDocument()
    expect(screen.getByText(/bob · 应用市场/)).toBeInTheDocument()
  })

  it('explains the several-owners case rather than leaving it puzzling', async () => {
    renderScan({
      submitter_sources: [
        { submitter: 'alice', source: 'console', requested_trust_tier: null },
        { submitter: 'bob', source: 'console', requested_trust_tier: null },
      ],
    })
    await waitForLoaded()
    expect(screen.getByText(/合并为同一次扫描/)).toBeInTheDocument()
  })

  it('says nothing about merging when there is exactly one submitter', async () => {
    renderScan({
      submitter_sources: [{ submitter: 'alice', source: 'console', requested_trust_tier: null }],
    })
    await waitForLoaded()
    expect(screen.queryByText(/合并为同一次扫描/)).toBeNull()
  })

  it('shows a submitter with no recorded channel without inventing one', async () => {
    // NULL source = the row predates the channel column; it is never defaulted
    // to "console" (gateway/router.py makes the same promise server-side).
    renderScan({
      submitter_sources: [{ submitter: 'alice', source: null, requested_trust_tier: null }],
    })
    await waitForLoaded()
    const line = screen.getByText(/提交者：/)
    expect(line.textContent).toContain('alice')
    expect(line.textContent).not.toContain('控制台')
  })

  it('echoes an unknown channel instead of rendering a translation key', async () => {
    renderScan({
      submitter_sources: [{ submitter: 'alice', source: 'cli', requested_trust_tier: null }],
    })
    await waitForLoaded()
    expect(screen.getByText(/alice · cli/)).toBeInTheDocument()
    expect(screen.queryByText(/submissionChannel\./)).toBeNull()
  })

  it('falls back to `submitters` when no per-name attribution came back', async () => {
    renderScan({ submitters: ['alice', 'bob'], submitter_sources: [] })
    await waitForLoaded()
    const line = screen.getByText(/提交者：/)
    expect(line.textContent).toContain('alice')
    expect(line.textContent).toContain('bob')
  })

  it('falls back to the legacy scalar when neither list came back', async () => {
    renderScan({ submitter: 'carol', submitters: [], submitter_sources: [] })
    await waitForLoaded()
    expect(screen.getByText(/carol/)).toBeInTheDocument()
  })

  it('renders no submitter line at all when nothing was recorded', async () => {
    renderScan({ submitter: '', submitters: [], submitter_sources: [] })
    await waitForLoaded()
    expect(screen.queryByText(/提交者：/)).toBeNull()
  })

  // 里程碑 F Task 14: the tier line above only covers the tier THIS viewer asked
  // for. An approver reading a deduplicated scan needs to see that some OTHER
  // submitter asked for a tier the verdict was not reached at.
  it('flags a submitter whose requested tier is not the tier the verdict was reached at', async () => {
    renderScan({
      judged_at_tier: 'internal',
      submitter_sources: [
        { submitter: 'alice', source: 'console', requested_trust_tier: 'internal' },
        { submitter: 'bob', source: 'marketplace', requested_trust_tier: 'public' },
      ],
    })
    await waitForLoaded()
    const line = screen.getByText(/提交者：/)
    // Only bob diverges. Printing the tier on alice's row too would repeat the
    // judged tier and bury the one row that matters.
    expect(line.textContent).toContain('请求层级 公开')
    expect(line.textContent).not.toContain('请求层级 内部')
  })

  it('does not flag a submitter whose tier the policy treats as the judged one', async () => {
    // Same pair the headline explains away as a name-only difference
    // (`tier_direction: 'equivalent'`). Flagging alice here while the paragraph
    // directly above says the verdict is unaffected is a contradiction the
    // reader has to resolve, and every false flag makes the real one - bob's -
    // easier to skip.
    renderScan({
      trust_tier: 'partner',
      judged_at_tier: 'internal',
      tier_direction: 'equivalent',
      submitter_sources: [
        { submitter: 'alice', source: 'console', requested_trust_tier: 'partner' },
        { submitter: 'bob', source: 'marketplace', requested_trust_tier: 'public' },
      ],
    })
    await waitForLoaded()
    const line = screen.getByText(/提交者：/)
    expect(line.textContent).not.toContain('请求层级 合作伙伴')
    expect(line.textContent).toContain('请求层级 公开')
  })

  it('still flags the dangerous divergence the server reported', async () => {
    renderScan({
      trust_tier: 'public',
      judged_at_tier: 'internal',
      tier_direction: 'looser',
      submitter_sources: [
        { submitter: 'alice', source: 'console', requested_trust_tier: 'public' },
      ],
    })
    await waitForLoaded()
    expect(screen.getByText(/提交者：/).textContent).toContain('请求层级 公开')
  })

  it('says nothing about a submitter whose request is not on record', async () => {
    // NULL = the row predates the column. It is never filled in from the scan's
    // judged tier, which would assert the very agreement the field exists to
    // stop assuming (gateway/router.py makes the same promise server-side).
    renderScan({
      judged_at_tier: 'internal',
      submitter_sources: [{ submitter: 'alice', source: 'console', requested_trust_tier: null }],
    })
    await waitForLoaded()
    const line = screen.getByText(/提交者：/)
    expect(line.textContent).toContain('alice')
    expect(line.textContent).not.toContain('请求层级')
  })
})
