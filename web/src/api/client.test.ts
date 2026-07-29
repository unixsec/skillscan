import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, SessionExpiredError, api, setSessionExpiredListener } from './client'
import { useApiData } from './useApiData'

// jsdom's `window.location` is redefinable here, so these tests stub the whole
// object: `assign` becomes an observable mock (jsdom would otherwise log "Not
// implemented: navigation") and `pathname`/`search` become the "where the user
// was" that the redirect has to carry into `?next=`.
const realLocation = Object.getOwnPropertyDescriptor(window, 'location')

function stubLocation(pathname: string, search = ''): ReturnType<typeof vi.fn> {
  const assign = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    writable: true,
    value: { pathname, search, href: `http://localhost${pathname}${search}`, assign },
  })
  return assign
}

function jsonResponse(status: number, body: unknown, errorCode?: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      // The backend's machine-readable error code (libs/common/errors.py's
      // ERROR_CODE_HEADER), present on every auth error it raises.
      ...(errorCode === undefined ? {} : { 'x-error-code': errorCode }),
    },
  })
}

function mockFetch(...responses: Response[]) {
  const fetchMock = vi.fn<typeof fetch>()
  for (const response of responses) fetchMock.mockResolvedValueOnce(response)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

// Typed like `vi.fn<typeof fetch>()` above: a bare `vi.fn()` widens to
// `Mock<Procedure | Constructable>`, which `setSessionExpiredListener` rejects.
let sessionCleared: ReturnType<typeof vi.fn<() => void>>

beforeEach(() => {
  sessionCleared = vi.fn<() => void>()
  // Registering a listener also resets the once-per-app redirect guard, so
  // each test starts from a document that has not yet bounced to /login.
  setSessionExpiredListener(sessionCleared)
})

afterEach(() => {
  setSessionExpiredListener(null)
  vi.unstubAllGlobals()
  if (realLocation) Object.defineProperty(window, 'location', realLocation)
})

describe('401 handling in the API client', () => {
  it('redirects to login with a next param carrying the current path and query', async () => {
    const assign = stubLocation('/scans', '?page=2&state=queued')
    mockFetch(jsonResponse(401, { detail: 'Not authenticated' }))

    const err = await api.get('/v1/scans?page=2').catch((e: unknown) => e)

    expect(err).toBeInstanceOf(SessionExpiredError)
    // Still an ApiError, so every existing `instanceof ApiError` branch keeps working.
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(401)
    expect(assign).toHaveBeenCalledTimes(1)
    expect(assign).toHaveBeenCalledWith('/login?next=%2Fscans%3Fpage%3D2%26state%3Dqueued')
    expect(sessionCleared).toHaveBeenCalled()
  })

  it('redirects only once when several panels 401 at the same time', async () => {
    const assign = stubLocation('/dashboard')
    mockFetch(
      jsonResponse(401, { detail: 'Not authenticated' }),
      jsonResponse(401, { detail: 'Not authenticated' }),
      jsonResponse(401, { detail: 'Not authenticated' }),
    )

    await Promise.all([
      api.get('/v1/a').catch(() => null),
      api.get('/v1/b').catch(() => null),
      api.get('/v1/c').catch(() => null),
    ])

    expect(assign).toHaveBeenCalledTimes(1)
  })

  it('treats a 401 on a download the same way (second fetch call site)', async () => {
    const assign = stubLocation('/reports')
    mockFetch(jsonResponse(401, { detail: 'Not authenticated' }))

    const err = await api.download('/v1/reports/x.csv', 'x.csv').catch((e: unknown) => e)

    expect(err).toBeInstanceOf(SessionExpiredError)
    expect(assign).toHaveBeenCalledWith('/login?next=%2Freports')
  })

  it('does not redirect when the login request itself is rejected', async () => {
    // Deliberately NOT on /login, so this proves the auth-endpoint exemption
    // on its own rather than passing via the "already on /login" guard below.
    const assign = stubLocation('/scans')
    mockFetch(jsonResponse(401, { detail: 'invalid credentials' }))

    const err = await api
      .post('/v1/admin/local/login', { username: 'a', password: 'b' })
      .catch((e: unknown) => e)

    // A wrong password must surface as an inline form error, not blow the
    // page away (which would also discard the message the user needs).
    expect(err).toBeInstanceOf(ApiError)
    expect(err).not.toBeInstanceOf(SessionExpiredError)
    expect((err as ApiError).detail).toBe('invalid credentials')
    expect(assign).not.toHaveBeenCalled()
  })

  it('does not loop when /v1/me 401s on the login page itself', async () => {
    const assign = stubLocation('/login', '?next=%2Fscans')
    mockFetch(jsonResponse(401, { detail: 'Not authenticated' }))

    await api.get('/v1/me').catch(() => null)

    // Without this guard: 401 -> assign('/login?next=/login') -> reload ->
    // SessionProvider fetches /v1/me -> 401 -> assign -> ... forever.
    expect(assign).not.toHaveBeenCalled()
  })

  it('does not redirect on a /v1/auth flow failure', async () => {
    const assign = stubLocation('/scans')
    mockFetch(jsonResponse(401, { detail: 'authentication required' }))

    const err = await api.post('/v1/auth/logout').catch((e: unknown) => e)

    expect(err).not.toBeInstanceOf(SessionExpiredError)
    expect(assign).not.toHaveBeenCalled()
  })

  // A state-changing route lists require_csrf BEFORE the role dependency and
  // FastAPI solves route-level dependencies first, so a write whose csrf_token
  // cookie is gone (but whose session cookie is not) fails CSRF at 403 and
  // never reaches the 401.
  //
  // PINNED VALUE: 'csrf_validation_failed' is the literal
  // apps/monolith/tests/test_dependencies.py's TestMachineReadableErrorCode
  // asserts the backend emits. Spelled out on both sides on purpose - a shared
  // constant would let a rename pass silently on both at once, which is the
  // exact failure this test exists to prevent.
  it('treats a 403 carrying the csrf_validation_failed code as a session expiry', async () => {
    const assign = stubLocation('/reviews')
    mockFetch(jsonResponse(403, { detail: 'CSRF validation failed' }, 'csrf_validation_failed'))

    const err = await api.post('/v1/reviews/r1/approve', {}).catch((e: unknown) => e)

    expect(err).toBeInstanceOf(SessionExpiredError)
    expect(assign).toHaveBeenCalledWith('/login?next=%2Freviews')
  })

  it('keys the expiry decision on the code, not on the human detail', async () => {
    // The regression this whole change is about: the detail text is written
    // for people and may be reworded, translated or punctuated at any time.
    // Here it is the OLD literal the client used to match on, with a code
    // saying "permission" - the code must win. If this ever starts redirecting,
    // the client has drifted back to matching prose.
    const assign = stubLocation('/reviews')
    mockFetch(jsonResponse(403, { detail: 'CSRF validation failed' }, 'forbidden'))

    const err = await api.post('/v1/reviews/r1/approve', {}).catch((e: unknown) => e)

    expect(err).not.toBeInstanceOf(SessionExpiredError)
    expect(assign).not.toHaveBeenCalled()
  })

  it('still surfaces the human detail as the error message', async () => {
    // The code is consumed instead of the detail, not as well as displaying
    // it: a user/log still needs the sentence.
    stubLocation('/reviews')
    mockFetch(jsonResponse(403, { detail: 'CSRF validation failed' }, 'csrf_validation_failed'))

    const err = await api.post('/v1/reviews/r1/approve', {}).catch((e: unknown) => e)

    expect((err as ApiError).detail).toBe('CSRF validation failed')
  })

  it.each([
    ['forbidden', 'forbidden'],
    [
      'this endpoint is not available to machine identities; use the /v1/market endpoints',
      'forbidden',
    ],
    ['exempting a hard-gate rule requires the admin role', undefined],
  ])('does not log the user out on a permission 403 (%s)', async (detail, code) => {
    const assign = stubLocation('/reviews')
    mockFetch(jsonResponse(403, { detail }, code))

    const err = await api.post('/v1/reviews/r1/approve', {}).catch((e: unknown) => e)

    // These answer a perfectly live session with "you may not do that".
    // Bouncing to /login would destroy a valid session over a role problem.
    // The third case has no code at all - a business-rule 403 raised as a bare
    // HTTPException - and must be treated as a refusal, never as expiry.
    expect(err).toBeInstanceOf(ApiError)
    expect(err).not.toBeInstanceOf(SessionExpiredError)
    expect(assign).not.toHaveBeenCalled()
    expect(sessionCleared).not.toHaveBeenCalled()
  })

  it('leaves a non-auth failure alone', async () => {
    const assign = stubLocation('/scans')
    mockFetch(jsonResponse(500, { detail: 'boom' }))

    const err = await api.get('/v1/scans').catch((e: unknown) => e)

    expect(err).toBeInstanceOf(ApiError)
    expect(err).not.toBeInstanceOf(SessionExpiredError)
    expect(assign).not.toHaveBeenCalled()
    expect(sessionCleared).not.toHaveBeenCalled()
  })
})

// THE SEAM. Task 3 (polling) and this task (401 -> login) are each correct in
// isolation and produce a new defect together: an expired session keeps
// hammering 401 at the 20s backoff cap forever, while the user watches a page
// that never navigates. Two green single-feature tests are exactly the
// evidence that misses this, so the combined scenario gets its own test.
describe('polling x session expiry (the seam)', () => {
  interface FakeStatus {
    status: string
  }

  async function flush() {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
  }

  async function advance(ms: number) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms)
    })
  }

  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('stops an in-flight poll when the session expires mid-poll', async () => {
    const assign = stubLocation('/scans/abc123')
    const fetchMock = mockFetch(
      jsonResponse(200, { status: 'queued' }),
      jsonResponse(401, { detail: 'Not authenticated' }),
    )

    const { result, unmount } = renderHook(() =>
      useApiData<FakeStatus>(() => api.get<FakeStatus>('/v1/scans/abc123'), [], {
        pollWhile: (d) => d.status !== 'done',
      }),
    )

    await flush()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(assign).not.toHaveBeenCalled()

    await advance(3000) // first poll interval -> 401
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(assign).toHaveBeenCalledTimes(1)
    expect(assign).toHaveBeenCalledWith('/login?next=%2Fscans%2Fabc123')

    // The whole point: zero further requests. Without the SessionExpiredError
    // branch, useApiData's catch would reschedule and this would be 5+ calls.
    await advance(120000)
    expect(fetchMock).toHaveBeenCalledTimes(2)

    // And no "Error: Not authenticated" text on the way out.
    expect(result.current.error).toBeNull()

    act(() => unmount())
  })

  it('still shows the error and keeps retrying on a transient failure', async () => {
    stubLocation('/scans/abc123')
    const fetchMock = mockFetch(
      jsonResponse(200, { status: 'queued' }),
      jsonResponse(503, { detail: 'upstream unavailable' }),
      jsonResponse(200, { status: 'queued' }),
    )

    const { result, unmount } = renderHook(() =>
      useApiData<FakeStatus>(() => api.get<FakeStatus>('/v1/scans/abc123'), [], {
        pollWhile: (d) => d.status !== 'done',
      }),
    )

    await flush()
    expect(fetchMock).toHaveBeenCalledTimes(1)

    await advance(3000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    // Reported as `pollError`, not `error`: a 503 on one background poll is
    // "what you are looking at may be stale", not "there is nothing to show
    // you". `error` is the one DataState renders INSTEAD of the page, and a
    // fully rendered scan must not blank out for 3 seconds over a blip.
    expect(result.current.pollError).toBe('upstream unavailable')
    expect(result.current.error).toBeNull()
    expect(result.current.data).toEqual({ status: 'queued' })

    await advance(5000)
    expect(fetchMock).toHaveBeenCalledTimes(3) // a 503 must NOT kill polling
    expect(result.current.pollError).toBeNull() // and the notice clears itself

    act(() => unmount())
  })

  it('does not render an auth error on the very first load', async () => {
    stubLocation('/scans')
    mockFetch(jsonResponse(401, { detail: 'Not authenticated' }))

    const { result, unmount } = renderHook(() =>
      useApiData<FakeStatus>(() => api.get<FakeStatus>('/v1/scans')),
    )

    await flush()

    // The page is navigating to /login; it must not flash the literal
    // "Error: Not authenticated" that this task exists to remove, and it must
    // not fall through to rendering children with null data either.
    expect(result.current.error).toBeNull()
    expect(result.current.loading).toBe(true)

    act(() => unmount())
  })
})
