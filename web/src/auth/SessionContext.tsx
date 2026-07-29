import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, ApiError, setSessionExpiredListener } from '../api/client'
import type { Session } from '../api/types'

interface SessionState {
  session: Session | null
  loading: boolean
  refresh: () => void
  logout: () => Promise<void>
}

// SECURITY (coding spec §9: "前端隐藏仅UX"): this context is ONLY used to
// decide what the UI shows - hiding a nav link for a role that doesn't have
// it is a convenience, never a security boundary. Every backend route
// independently re-checks the caller's role regardless of what this context
// says, so a tampered/absent client-side session state can only ever make
// the UI show LESS, never grant more access than the backend allows.
const SessionCtx = createContext<SessionState>({
  session: null,
  loading: true,
  refresh: () => {},
  logout: async () => {},
})

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const [generation, setGeneration] = useState(0)

  // A 401/CSRF-expiry on ANY request redirects to /login from inside
  // client.ts. Dropping the in-memory session here too matters because the
  // redirect is not instantaneous: React keeps rendering until the browser
  // unloads the document, and a stale session object during that window makes
  // RequireSession keep rendering protected pages (and, if the navigation is
  // ever swapped for an SPA one, would make the login page think it is already
  // signed in).
  useEffect(() => {
    setSessionExpiredListener(() => setSession(null))
    return () => setSessionExpiredListener(null)
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .get<Session>('/v1/me')
      .then((s) => {
        if (!cancelled) setSession(s)
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          if (err instanceof ApiError && err.status === 401) {
            setSession(null)
          } else {
            setSession(null)
          }
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [generation])

  const refresh = () => setGeneration((g) => g + 1)

  // POST /v1/auth/logout revokes the session server-side (Redis) and clears
  // every session/CSRF cookie regardless of which auth method was in use;
  // refresh() re-fetches /v1/me, which now 401s, setting session to null -
  // App.tsx's RequireAuth guard then redirects to /login on its own, no
  // navigation call needed here.
  const logout = async () => {
    try {
      await api.post('/v1/auth/logout')
    } finally {
      refresh()
    }
  }

  return (
    <SessionCtx.Provider value={{ session, loading, refresh, logout }}>
      {children}
    </SessionCtx.Provider>
  )
}

export function useSession(): SessionState {
  return useContext(SessionCtx)
}

export function hasAnyRole(session: Session | null, ...roles: string[]): boolean {
  if (!session) return false
  return roles.some((r) => session.roles.includes(r))
}
