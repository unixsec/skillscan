import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { SessionProvider, useSession } from './auth/SessionContext'
import { I18nProvider, useI18n } from './i18n/I18nContext'
import { Layout } from './components/Layout'
import { ToastProvider } from './components/Toast'
import { LoginPage, safeNextPath } from './pages/Login'
import { DashboardPage } from './pages/Dashboard'
import { ScansPage } from './pages/Scans'
import { ScanDetailPage } from './pages/ScanDetail'
import { ReviewsPage } from './pages/Reviews'
import { AllowlistPage } from './pages/Allowlist'
import { InventoryListPage, InventoryDetailPage } from './pages/Inventory'
import { ReevalPage } from './pages/Reeval'
import { ReconciliationPage } from './pages/Reconciliation'
import { ReportsPage } from './pages/Reports'
import { AuditPage } from './pages/Audit'
import { AdminEnginesPage } from './pages/admin/Engines'
import { AdminPolicyPage } from './pages/admin/Policy'
import { AdminUsersPage } from './pages/admin/Users'
import { AdminIntelPage } from './pages/admin/Intel'
import { AdminOwnershipPage } from './pages/admin/Ownership'
import { AdminBreakGlassPage } from './pages/admin/BreakGlass'

export function RequireSession({ children }: { children: React.ReactNode }) {
  const { session, loading } = useSession()
  const { t } = useI18n()
  const location = useLocation()
  // SECURITY (UX only): redirects to /login if there's no session, purely so
  // the app doesn't render pages full of 401s - the backend independently
  // rejects every request regardless of what this check decides.
  if (loading) {
    return (
      <p className="hint" style={{ padding: '2rem' }}>
        {t('common.loading')}
      </p>
    )
  }
  if (!session) {
    // Mirrors client.ts's own 401 redirect (`next=<path+search>`), so a
    // session that is ALREADY gone before this component even mounts (e.g. a
    // stale tab reopened after the session expired elsewhere) still lands the
    // user back where they were instead of the dashboard. Reused rather than
    // re-derived: safeNextPath is the SAME sanitizer LoginPage applies when it
    // reads the param back, so there is exactly one place that decides what
    // counts as a safe same-origin path, not two independently maintained
    // ones that could drift.
    const next = safeNextPath(`${location.pathname}${location.search}`)
    return <Navigate to={`/login?next=${encodeURIComponent(next)}`} replace />
  }
  return <>{children}</>
}

function NotFoundPage() {
  const { t } = useI18n()
  return (
    <div>
      <h1>{t('notFound.title')}</h1>
      <p className="hint">{t('notFound.description')}</p>
      <p>
        <Link to="/">{t('notFound.backHome')}</Link>
      </p>
    </div>
  )
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireSession>
            <Layout />
          </RequireSession>
        }
      >
        <Route path="/" element={<DashboardPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
        <Route path="/reviews" element={<ReviewsPage />} />
        <Route path="/allowlist" element={<AllowlistPage />} />
        <Route path="/inventory" element={<InventoryListPage />} />
        <Route path="/inventory/:skillId" element={<InventoryDetailPage />} />
        <Route path="/reeval" element={<ReevalPage />} />
        <Route path="/reconciliation" element={<ReconciliationPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/admin/engines" element={<AdminEnginesPage />} />
        <Route path="/admin/policy" element={<AdminPolicyPage />} />
        <Route path="/admin/users" element={<AdminUsersPage />} />
        <Route path="/admin/intel" element={<AdminIntelPage />} />
        <Route path="/admin/ownership" element={<AdminOwnershipPage />} />
        <Route path="/admin/breakglass" element={<AdminBreakGlassPage />} />
        {/* Catch-all lives INSIDE the guarded layout group, not as a
            top-level sibling of /login: a typo'd/stale in-app URL should
            still get the same nav chrome and session check as every real
            page, not a bare unstyled page - and an unauthenticated hit still
            redirects to /login first via RequireSession, same as any other
            protected route. */}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <I18nProvider>
        <SessionProvider>
          <ToastProvider>
            <AppRoutes />
          </ToastProvider>
        </SessionProvider>
      </I18nProvider>
    </BrowserRouter>
  )
}
