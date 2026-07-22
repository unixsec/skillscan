import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { useSession } from '../auth/SessionContext'
import { useI18n } from '../i18n/I18nContext'

// NOTE: normal SSO (OIDC/SAML) has no login-callback endpoint wired yet in
// this backend (see docs/stories/BACKLOG.md's M8 status note). Two working
// session-creation paths exist: break-glass (emergency, four-eyes, admin
// only) and local account (2026-07-13 addition, standing username/password
// path covering all four roles - see apps/monolith/modules/admin/local_auth.py).
type LoginTab = 'breakglass' | 'local'

function BreakglassForm() {
  const [credential, setCredential] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const { refresh } = useSession()
  const { t } = useI18n()
  const navigate = useNavigate()

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await api.post('/v1/admin/breakglass/login', { credential, totp_code: totpCode })
      refresh()
      navigate('/')
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : t('login.failed'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      autoComplete="off"
      style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}
    >
      <label>
        {t('login.credential')}
        {/* SECURITY: a break-glass credential must NEVER be saved or
            autofilled by the browser's password manager - a stale autofilled
            value silently overrides what the operator types and, after a
            credential rotation, makes every login fail with the RIGHT TOTP
            but the WRONG (old, autofilled) credential. autoComplete=
            "new-password" is the reliable cross-browser way to suppress
            autofill of a saved password on a type=password field. */}
        <input
          type="password"
          name="breakglass-credential"
          autoComplete="new-password"
          value={credential}
          onChange={(e) => setCredential(e.target.value)}
          required
        />
      </label>
      <label>
        {t('login.totpCode')}
        <input
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          value={totpCode}
          onChange={(e) => setTotpCode(e.target.value)}
          required
        />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" className="primary" disabled={submitting}>
        {submitting ? t('login.signingIn') : t('login.signIn')}
      </button>
    </form>
  )
}

function LocalAccountForm() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const { refresh } = useSession()
  const { t } = useI18n()
  const navigate = useNavigate()

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await api.post('/v1/admin/local/login', { username, password })
      refresh()
      navigate('/')
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : t('login.failed'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      autoComplete="off"
      style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}
    >
      <label>
        {t('login.username')}
        <input
          type="text"
          name="local-username"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
      </label>
      <label>
        {t('login.password')}
        <input
          type="password"
          name="local-password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" className="primary" disabled={submitting}>
        {submitting ? t('login.signingIn') : t('login.signIn')}
      </button>
    </form>
  )
}

export function LoginPage() {
  const [tab, setTab] = useState<LoginTab>('local')
  const { t } = useI18n()

  return (
    <div className="card" style={{ maxWidth: 360, margin: '4rem auto' }}>
      <h1>{t('login.title')}</h1>
      <p className="hint">{t('login.description')}</p>
      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
        <button
          type="button"
          className={tab === 'local' ? 'primary' : ''}
          aria-pressed={tab === 'local'}
          onClick={() => setTab('local')}
        >
          {t('login.tabLocal')}
        </button>
        <button
          type="button"
          className={tab === 'breakglass' ? 'primary' : ''}
          aria-pressed={tab === 'breakglass'}
          onClick={() => setTab('breakglass')}
        >
          {t('login.tabBreakglass')}
        </button>
      </div>
      {tab === 'local' ? <LocalAccountForm /> : <BreakglassForm />}
    </div>
  )
}
