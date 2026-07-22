import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { SessionProvider, useSession } from './auth/SessionContext'
import { I18nProvider, useI18n } from './i18n/I18nContext'
import { Layout } from './components/Layout'
import { ToastProvider } from './components/Toast'
import { LoginPage } from './pages/Login'
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
import { AdminBreakGlassPage } from './pages/admin/BreakGlass'

function RequireSession({ children }: { children: React.ReactNode }) {
  const { session, loading } = useSession()
  const { t } = useI18n()
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
  if (!session) return <Navigate to="/login" replace />
  return <>{children}</>
}

function AppRoutes() {
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
        <Route path="/admin/breakglass" element={<AdminBreakGlassPage />} />
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
