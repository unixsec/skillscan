import { render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../../i18n/I18nContext'
import { ToastProvider } from '../../components/Toast'
import { AdminEnginesPage } from './Engines'
import type { EngineHealth, EngineHealthReport, EngineInfo } from '../../api/types'

// The user-visible half of milestone C acceptance criterion 8: an operator
// looking at this page must be able to tell an engine that RETURNED AN ERROR
// from one that NEVER REPORTED AT ALL. The unit tests in engineHealth.test.ts
// prove the rules; this proves the page actually applies them, on the real
// markup, through the real translator.

const { mockGet, mockPatch } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPatch: vi.fn() }))

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
    api: { get: mockGet, patch: mockPatch },
    ApiError,
    SessionExpiredError,
    setSessionExpiredListener: () => {},
  }
})

function engine(overrides: Partial<EngineInfo> = {}): EngineInfo {
  return {
    name: 'bandit',
    version: null,
    version_unavailable_reason: 'sandboxed_image',
    required: false,
    enabled: true,
    capabilities: ['sandboxed'],
    ...overrides,
  }
}

function health(overrides: Partial<EngineHealth> = {}): EngineHealth {
  return {
    name: 'bandit',
    observed_scans: 5,
    counts: { ok: 5, partial: 0, error: 0, not_reported: 0, unreadable: 0 },
    last_scan_id: 'scan-1',
    last_recorded_at: '2026-07-29T12:00:00',
    last_report_state: 'reported',
    last_engine_status: 'ok',
    last_analyze_duration_ms: 42,
    max_analyze_duration_ms: 90,
    measured_duration_count: 5,
    last_finding_count: 0,
    last_error: null,
    not_reported_attribution: null,
    not_reported_attribution_basis: null,
    ...overrides,
  }
}

function respondWith(engines: EngineInfo[], report: EngineHealthReport | Error) {
  mockGet.mockImplementation((url: string) => {
    if (url === '/v1/admin/engines') return Promise.resolve({ engines })
    if (url === '/v1/admin/engines/health') {
      return report instanceof Error ? Promise.reject(report) : Promise.resolve(report)
    }
    return Promise.reject(new Error(`unexpected url ${url}`))
  })
}

function report(engines: EngineHealth[], overrides: Partial<EngineHealthReport> = {}) {
  return {
    window: {
      requested_scans: 50,
      observed_scans: 5,
      started_at: '2026-07-29T10:00:00',
      ended_at: '2026-07-29T12:00:00',
    },
    engines,
    unregistered_engines: [],
    ...overrides,
  }
}

function renderPage() {
  render(
    <I18nProvider>
      <ToastProvider>
        <AdminEnginesPage />
      </ToastProvider>
    </I18nProvider>,
  )
}

function rowFor(name: string): HTMLElement {
  return screen.getByText(name, { exact: false }).closest('tr') as HTMLElement
}

beforeEach(() => {
  mockGet.mockReset()
  mockPatch.mockReset()
})

describe('an engine that errored and one that never reported', () => {
  beforeEach(() => {
    respondWith(
      [engine({ name: 'osv-scanner' }), engine({ name: 'aig-mcp-scan' })],
      report([
        health({
          name: 'osv-scanner',
          last_engine_status: 'error',
          last_error: 'adapter exited 1',
          counts: { ok: 0, partial: 0, error: 5, not_reported: 0, unreadable: 0 },
        }),
        health({
          name: 'aig-mcp-scan',
          last_report_state: 'not_reported',
          last_engine_status: null,
          last_analyze_duration_ms: null,
          max_analyze_duration_ms: null,
          measured_duration_count: 0,
          last_finding_count: null,
          last_error: 'no findings reported at findings/scan-1/aig-mcp-scan.json',
          not_reported_attribution: 'llm_endpoint_unconfigured',
          not_reported_attribution_basis: 'current_config',
          counts: { ok: 0, partial: 0, error: 0, not_reported: 5, unreadable: 0 },
        }),
      ]),
    )
  })

  it('shows two different, translated labels', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('返回错误')).toBeInTheDocument())
    expect(screen.getByText('从未上报')).toBeInTheDocument()
    // Neither raw wire value reaches the screen.
    expect(screen.queryByText('not_reported')).toBeNull()
    expect(screen.queryByText('reported')).toBeNull()
  })

  it('gives the two rows different badge colours', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('返回错误')).toBeInTheDocument())
    expect(screen.getByText('返回错误').className).not.toBe(
      screen.getByText('从未上报').className,
    )
  })

  it('explains the never-reported engine as a CURRENT-CONFIG fact, not an observation', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByText('从未上报')).toBeInTheDocument())
    const row = rowFor('aig-mcp-scan')
    const attribution = within(row).getByText('当前配置：本服务未配置内部 LLM 端点')
    expect(attribution.getAttribute('title')).toContain('也不是这些扫描当时的配置')
    // The claim about the OTHER process stays conditional on screen.
    expect(attribution.getAttribute('title')).toContain('若两边配置不一致')
  })
})

describe('the never-reported causes that cannot be known', () => {
  it('says the cause was not recorded rather than guessing one', async () => {
    respondWith(
      [engine({ name: 'yara' })],
      report([
        health({
          name: 'yara',
          last_report_state: 'not_reported',
          last_engine_status: null,
          last_analyze_duration_ms: null,
          max_analyze_duration_ms: null,
          measured_duration_count: 0,
          last_finding_count: null,
          not_reported_attribution: null,
          counts: { ok: 0, partial: 0, error: 0, not_reported: 5, unreadable: 0 },
        }),
      ]),
    )
    renderPage()
    await waitFor(() => expect(screen.getByText('原因未记录')).toBeInTheDocument())
  })
})

describe('the three duration states on screen', () => {
  it('renders 0 as a measurement and null as not-measured, never as the same cell', async () => {
    respondWith(
      [engine({ name: 'static-keyword' }), engine({ name: 'yara' }), engine({ name: 'bandit' })],
      report([
        health({ name: 'static-keyword', last_analyze_duration_ms: 0, max_analyze_duration_ms: 0 }),
        health({
          name: 'yara',
          last_analyze_duration_ms: null,
          max_analyze_duration_ms: null,
          measured_duration_count: 0,
        }),
        health({ name: 'bandit', last_analyze_duration_ms: 42 }),
      ]),
    )
    renderPage()
    await waitFor(() => expect(screen.getByText('<1 毫秒')).toBeInTheDocument())
    expect(screen.getByText('未测量')).toBeInTheDocument()
    expect(screen.getByText('42 毫秒')).toBeInTheDocument()
  })
})

describe('the question this page answers is stated on it', () => {
  it('names the window the counts are computed over', async () => {
    respondWith([engine({ name: 'bandit' })], report([health()]))
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/最近 5 次仍有记录的扫描/)).toBeInTheDocument(),
    )
  })

  it('an empty retention window makes no claim about any engine', async () => {
    respondWith(
      [engine({ name: 'bandit' })],
      report([], {
        window: { requested_scans: 50, observed_scans: 0, started_at: null, ended_at: null },
      }),
    )
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/没有记录不等于引擎没有上报/)).toBeInTheDocument(),
    )
    // The engine row still renders, and reads as "no record", never as a failure.
    expect(screen.getByText('窗口内无记录')).toBeInTheDocument()
  })

  it('a failed health read keeps the toggle console usable and is labelled as a read failure', async () => {
    const failure = new Error('boom') as Error & { detail: string }
    failure.detail = 'boom'
    respondWith([engine({ name: 'bandit' })], failure)
    renderPage()
    await waitFor(() => expect(screen.getByText('停用')).toBeInTheDocument())
    expect(screen.getByText(/这是读取失败，不是引擎的状态/)).toBeInTheDocument()
  })
})

describe('version', () => {
  it('says why a sandbox engine has no version instead of showing a bare dash', async () => {
    respondWith([engine({ name: 'bandit' })], report([health()]))
    renderPage()
    await waitFor(() => expect(screen.getByText('不可读取（沙箱镜像）')).toBeInTheDocument())
  })
})

describe('health rows for engines the deployment no longer lists', () => {
  it('surfaces them instead of dropping them on the join', async () => {
    respondWith(
      [engine({ name: 'bandit' })],
      report([health()], { unregistered_engines: ['osv_scanner'] }),
    )
    renderPage()
    await waitFor(() => expect(screen.getByText(/osv_scanner/)).toBeInTheDocument())
  })
})
