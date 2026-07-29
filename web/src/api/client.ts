// BFF API client (coding spec §16, INV-16): every request carries the
// session via an HttpOnly cookie the browser attaches automatically (never
// read/stored in JS here) - `credentials: 'include'` is what makes that
// happen from the frontend's side. State-changing requests additionally echo
// the non-HttpOnly `csrf_token` cookie back as a header (double-submit CSRF
// pattern) - a cross-origin forger's browser attaches the cookie but can't
// read its value to also set the header.
const CSRF_COOKIE_NAME = 'csrf_token'
const CSRF_HEADER_NAME = 'x-csrf-token'
const SAFE_METHODS = new Set(['GET', 'HEAD'])

export class ApiError extends Error {
  status: number
  detail: string

  constructor(status: number, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

// A dead session is not a per-request error: it means the whole app has to go
// back to /login. Subclassing ApiError keeps every existing
// `err instanceof ApiError` branch working unchanged, while giving callers -
// above all useApiData's polling loop - a way to tell "session gone, stop"
// apart from "transient failure, retry". Without that distinction an expired
// session polls on forever at the 20s backoff cap.
export class SessionExpiredError extends ApiError {
  constructor(status: number, detail: string) {
    super(status, detail)
    this.name = 'SessionExpiredError'
  }
}

const LOGIN_PATH = '/login'

// Endpoints whose NORMAL failure mode is an auth error, and which therefore
// must never trigger the redirect. Two families, both verified against the
// backend routers:
//   - everything under /v1/auth (login_router.py's prefix): oidc/login,
//     oidc/callback, saml/login, saml/acs, logout. All of these 401 as their
//     ordinary "that login attempt failed" answer.
//   - */login on the two password paths the console actually posts to,
//     /v1/admin/local/login and /v1/admin/breakglass/login (admin/router.py).
//     A wrong password there must render an inline form error, not reload the
//     page - a reload would discard the very message the user needs.
// The */login suffix is a rule rather than a literal list so a login route
// added later is covered without anyone remembering to edit this file, which
// is the inverse of the MAINTENANCE_GUIDE §4.2 mistake (an enumeration of
// specific names that silently exempted every type nobody thought to add).
function isAuthEndpoint(path: string): boolean {
  const withoutQuery = path.split('?')[0].replace(/\/+$/, '')
  return (
    withoutQuery === '/v1/auth' ||
    withoutQuery.startsWith('/v1/auth/') ||
    withoutQuery.endsWith('/login') ||
    withoutQuery.endsWith('/logout')
  )
}

// The backend's machine-readable error contract (libs/common/errors.py):
// `detail` is a sentence written for a human and may be reworded, punctuated
// or translated at any time; this header carries a stable code a program may
// branch on. Matching the code instead of the detail is the whole point - the
// previous version of this file compared `detail` to the literal
// "CSRF validation failed", so any rewording on the backend would have taken
// the branch below dark with nothing turning red.
const ERROR_CODE_HEADER = 'x-error-code'
// Pinned on both sides: apps/monolith/tests/test_dependencies.py's
// TestMachineReadableErrorCode asserts the backend emits exactly this value,
// client.test.ts asserts this file consumes exactly this value. Deliberately
// spelled out in both places rather than shared, so a rename cannot pass
// silently on both sides at once.
const CSRF_FAILURE_CODE = 'csrf_validation_failed'

// Does this response mean "your session is no longer valid"?
//
// 401 is the ordinary case: the auth dependency raises
// AuthenticationError(401, "authentication required") for a missing OR expired
// session cookie - identical body either way, so the status is the only usable
// signal. (Note it is NOT the string "Not authenticated"; nothing in this
// backend produces that.)
//
// 403 is the case that is easy to get wrong. `require_csrf` is a ROUTE
// DEPENDENCY listed before the role dependency, and FastAPI solves route-level
// dependencies first, so on the ~20 state-changing routes CSRF is checked
// BEFORE authentication. It short-circuits when no session cookie is present,
// which is why the common expiry still surfaces as 401 (the session cookie and
// the CSRF cookie are both gone). But a session cookie can outlive the
// csrf_token cookie, and then a write gets 403 while reads keep working.
// Handling only 401 would mean this works for reads and silently fails for
// exactly the actions that matter. Every OTHER 403 (require_role's
// "forbidden", the machine-identity refusal, business-rule refusals) is a
// permission answer to a perfectly live session and must never log the user
// out - which is what the code, not the status, distinguishes.
function isSessionExpiry(status: number, errorCode: string | null, path: string): boolean {
  if (isAuthEndpoint(path)) return false
  if (status === 401) return true
  return status === 403 && errorCode === CSRF_FAILURE_CODE
}

type SessionExpiredListener = () => void
let sessionExpiredListener: SessionExpiredListener | null = null
let redirectStarted = false

// SessionProvider registers a callback that drops the in-memory session, so a
// stale session object cannot survive into the login page. Registering also
// resets the one-shot redirect guard: a fresh provider means a fresh document
// (or, in tests, a fresh case) that has not bounced to /login yet.
export function setSessionExpiredListener(listener: SessionExpiredListener | null): void {
  sessionExpiredListener = listener
  redirectStarted = false
}

function handleSessionExpired(): void {
  sessionExpiredListener?.()
  // Already on the login page? Redirecting there again would loop forever:
  // SessionProvider fetches /v1/me on every mount, which 401s while logged
  // out, which would assign('/login') again, which reloads, which fetches
  // /v1/me... The `next` param would end up pointing at /login as well.
  if (window.location.pathname === LOGIN_PATH) return
  if (redirectStarted) return
  redirectStarted = true
  const next = window.location.pathname + window.location.search
  window.location.assign(`${LOGIN_PATH}?next=${encodeURIComponent(next)}`)
}

// Single failure path for BOTH fetch call sites below. A per-page or
// per-helper 401 check is how this feature silently stops existing for
// whichever call site got forgotten.
async function toApiError(response: Response, path: string): Promise<ApiError> {
  let detail = response.statusText
  try {
    const errorBody: unknown = await response.json()
    if (errorBody && typeof errorBody === 'object' && 'detail' in errorBody) {
      detail = String((errorBody as { detail: unknown }).detail)
    }
  } catch {
    // response body wasn't JSON - keep statusText
  }
  if (isSessionExpiry(response.status, response.headers.get(ERROR_CODE_HEADER), path)) {
    handleSessionExpired()
    return new SessionExpiredError(response.status, detail)
  }
  return new ApiError(response.status, detail)
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`))
  return match ? decodeURIComponent(match[1]) : null
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  formData?: FormData,
): Promise<T> {
  const headers: Record<string, string> = {}
  if (!SAFE_METHODS.has(method)) {
    const csrfToken = readCookie(CSRF_COOKIE_NAME)
    if (csrfToken) headers[CSRF_HEADER_NAME] = csrfToken
  }
  if (formData === undefined && body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(path, {
    method,
    credentials: 'include',
    headers,
    body: formData ?? (body === undefined ? undefined : JSON.stringify(body)),
  })

  if (!response.ok) {
    throw await toApiError(response, path)
  }
  if (response.status === 204) return undefined as T
  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    return (await response.json()) as T
  }
  return (await response.text()) as T
}

// Fetch a binary/attachment endpoint and trigger a browser download. Unlike a
// plain `<a href download>`, this sends the session cookie via
// `credentials: 'include'`, and - critically - fails LOUDLY on a non-OK
// response (auth error, 500, ...) by throwing ApiError, instead of silently
// saving the error page/JSON to disk under a `.csv`/`.pdf` name (which is
// exactly what made "export" look like it produced an unopenable file).
async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(path, { method: 'GET', credentials: 'include' })
  if (!response.ok) {
    throw await toApiError(response, path)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
  } finally {
    URL.revokeObjectURL(url)
  }
}

export const api = {
  get: <T>(path: string): Promise<T> => request<T>('GET', path),
  post: <T>(path: string, body?: unknown): Promise<T> => request<T>('POST', path, body),
  postForm: <T>(path: string, formData: FormData): Promise<T> =>
    request<T>('POST', path, undefined, formData),
  patch: <T>(path: string, body?: unknown): Promise<T> => request<T>('PATCH', path, body),
  put: <T>(path: string, body?: unknown): Promise<T> => request<T>('PUT', path, body),
  delete: <T>(path: string): Promise<T> => request<T>('DELETE', path),
  download,
}
