import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { AppRoutes, RequireSession } from './App'
import { I18nProvider } from './i18n/I18nContext'
import { ToastProvider } from './components/Toast'
import type { Session } from './api/types'

const { mockUseSession } = vi.hoisted(() => ({ mockUseSession: vi.fn() }))

// Layout.tsx also pulls `hasAnyRole` from this module - importOriginal keeps
// that (and everything else) real, so only the one hook this test actually
// drives gets replaced.
vi.mock('./auth/SessionContext', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./auth/SessionContext')>()
  return { ...actual, useSession: mockUseSession }
})

function LoginProbe() {
  // Renders the raw query string so a test can assert on the EXACT encoded
  // `next` value, not just "some redirect happened".
  const location = useLocation()
  return <div data-testid="login-search">{location.search}</div>
}

function renderGuarded(initialPath: string) {
  render(
    <MemoryRouter initialEntries={[initialPath]}>
      <I18nProvider>
        <Routes>
          <Route path="/login" element={<LoginProbe />} />
          <Route
            path="*"
            element={
              <RequireSession>
                <div>protected content</div>
              </RequireSession>
            }
          />
        </Routes>
      </I18nProvider>
    </MemoryRouter>,
  )
}

// RequireSession loses where the user was (task 10, item 2): a session-less
// hit used to bounce to a bare /login with no `next`, silently relying on
// client.ts's OWN redirect (a full document navigation) to win the race and
// carry the real `next` instead. Exercising the actual round trip through
// safeNextPath - not just checking a string constant exists - is what would
// have caught that regression.
describe('RequireSession', () => {
  it('redirects to /login with the current path+search percent-encoded as next', () => {
    mockUseSession.mockReturnValue({ session: null, loading: false })
    renderGuarded('/scans/scan-1?state=queued')
    expect(screen.getByTestId('login-search').textContent).toBe(
      `?next=${encodeURIComponent('/scans/scan-1?state=queued')}`,
    )
  })

  it('still produces a same-origin next for the dashboard root', () => {
    mockUseSession.mockReturnValue({ session: null, loading: false })
    renderGuarded('/')
    expect(screen.getByTestId('login-search').textContent).toBe(`?next=${encodeURIComponent('/')}`)
  })

  it('renders children once a session exists, no redirect', () => {
    mockUseSession.mockReturnValue({ session: { subject: 'alice', roles: [], tier: 'public' }, loading: false })
    renderGuarded('/scans')
    expect(screen.getByText('protected content')).toBeInTheDocument()
    expect(screen.queryByTestId('login-search')).toBeNull()
  })
})

// No catch-all route (task 10, item 1): an unmatched path used to render
// nothing (or, once inside the guarded layout group, whatever the parent
// route's Outlet last showed) instead of a real 404. This renders the ACTUAL
// route table from App.tsx, not a reconstructed stand-in, so a typo'd
// `path="*"` or a route ordering mistake would fail it too.
describe('AppRoutes catch-all', () => {
  const session: Session = { subject: 'alice', roles: ['admin'], tier: 'internal' }

  function renderApp(initialPath: string) {
    mockUseSession.mockReturnValue({ session, loading: false, refresh: vi.fn(), logout: vi.fn() })
    render(
      <MemoryRouter initialEntries={[initialPath]}>
        <I18nProvider>
          <ToastProvider>
            <AppRoutes />
          </ToastProvider>
        </I18nProvider>
      </MemoryRouter>,
    )
  }

  it('renders the 404 page for an unknown path instead of a blank Outlet', () => {
    renderApp('/this-route-does-not-exist')
    expect(screen.getByText('404 - 页面不存在')).toBeInTheDocument()
  })

  it('a known route still resolves normally alongside the catch-all', () => {
    renderApp('/scans')
    expect(screen.queryByText('404 - 页面不存在')).toBeNull()
  })
})
