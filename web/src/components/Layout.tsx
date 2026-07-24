import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { LogOut, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { hasAnyRole, useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'
import type { Locale } from '../i18n/translations'
import { NAV_GROUP_LABEL_KEY, NAV_GROUP_ORDER, NAV_ITEMS } from '../nav/navItems'
import { CommandPalette } from './CommandPalette'
import { useToast } from './Toast'

const NAV_COLLAPSED_KEY = 'skillscan.nav.collapsed'

function LanguageToggle() {
  const { locale, setLocale, t } = useI18n()
  return (
    <label style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center', fontSize: '0.85rem' }}>
      {t('app.language')}
      <select
        value={locale}
        onChange={(e) => setLocale(e.target.value as Locale)}
        style={{ padding: '0.15rem 0.4rem' }}
      >
        <option value="zh">中文</option>
        <option value="en">English</option>
      </select>
    </label>
  )
}

export function Layout() {
  const { session, loading, logout } = useSession()
  const { t } = useI18n()
  const toast = useToast()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(NAV_COLLAPSED_KEY) === '1')

  async function handleLogout() {
    try {
      await logout()
    } catch {
      toast.error(t('app.logoutFailed'))
    }
  }

  useEffect(() => {
    localStorage.setItem(NAV_COLLAPSED_KEY, collapsed ? '1' : '0')
  }, [collapsed])

  const visibleItems = NAV_ITEMS.filter((item) => !item.roles || hasAnyRole(session, ...item.roles))

  return (
    <div className={collapsed ? 'app-shell app-shell-collapsed' : 'app-shell'}>
      <nav className="app-nav" aria-label="Primary">
        <div className="app-brand">
          <span className="app-brand-mark" aria-hidden="true">
            S
          </span>
          {!collapsed && <span className="app-brand-title">{t('app.title')}</span>}
          <button
            type="button"
            className="nav-collapse-toggle"
            onClick={() => setCollapsed((c) => !c)}
            aria-label={collapsed ? t('app.expandNav') : t('app.collapseNav')}
            title={collapsed ? t('app.expandNav') : t('app.collapseNav')}
          >
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        </div>
        <div className="nav-links">
          {NAV_GROUP_ORDER.map((group) => {
            const groupItems = visibleItems.filter((item) => item.group === group)
            if (groupItems.length === 0) return null
            return (
              <div className="nav-group" key={group}>
                {!collapsed && <div className="nav-group-label">{t(NAV_GROUP_LABEL_KEY[group])}</div>}
                {groupItems.map((item) => {
                  const Icon = item.icon
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      className={({ isActive }) => (isActive ? 'nav-link nav-link-active' : 'nav-link')}
                      end={item.to === '/'}
                      title={collapsed ? t(item.labelKey) : undefined}
                    >
                      <Icon size={16} className="nav-link-icon" aria-hidden="true" />
                      {!collapsed && <span>{t(item.labelKey)}</span>}
                    </NavLink>
                  )
                })}
              </div>
            )
          })}
        </div>
      </nav>
      <div className="app-body">
        <header className="app-header">
          <div className="app-eyebrow">{t('app.eyebrow')}</div>
          <div className="app-header-meta">
            {!loading && session && (
              <span className="app-session">
                {session.subject} ({session.roles.join(', ') || '—'})
              </span>
            )}
            <span className="status-pill">
              <span className="status-dot" aria-hidden="true" />
              {t('app.statusOnline')}
            </span>
            <LanguageToggle />
            {!loading && session && (
              <button
                type="button"
                className="logout-button"
                onClick={handleLogout}
                aria-label={t('app.logout')}
                title={t('app.logout')}
              >
                <LogOut size={15} aria-hidden="true" />
                {t('app.logout')}
              </button>
            )}
          </div>
        </header>
        <main className="app-content">
          <Outlet />
        </main>
      </div>
      <CommandPalette items={visibleItems} />
    </div>
  )
}
