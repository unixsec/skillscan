import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, SessionExpiredError } from './client'

interface ApiDataState<T> {
  data: T | null
  loading: boolean
  // A load that left NOTHING usable on screen: the first load failed (or a
  // reload / deps change did, which is the same thing from the reader's side -
  // what is rendered no longer describes what was asked for). This is the only
  // one `DataState` renders INSTEAD of the children, because it is the only one
  // where there is nothing better to render.
  error: string | null
  // A BACKGROUND REFRESH failed while data is still on screen. Deliberately a
  // second field rather than more writes to `error`:
  //
  //   - `error` blanks the page (DataState returns early on it). Blanking a
  //     fully rendered scan because one 3-second poll got a 503 - and then
  //     unblanking it 3 seconds later - is strictly worse than showing the
  //     data with a note that it may be stale.
  //   - the two facts have different lifetimes: "we have nothing to show you"
  //     stands until something changes, "the last refresh failed, still
  //     retrying" is expected to clear itself.
  //
  // One string could only ever express one of them, and the version that
  // expressed the wrong one left a transient poll failure rendering its error
  // paragraph forever, on top of data that kept refreshing successfully
  // underneath it (it was cleared only on the initial load). Both fields are
  // cleared by ANY successful load, poll included.
  pollError: string | null
  reload: () => void
}

interface UseApiDataOptions<T> {
  // Called with the freshly fetched data after every successful load. While
  // it returns true, polling continues; the hook itself has no notion of
  // what a "terminal" state looks like - that belongs to the caller.
  pollWhile?: (data: T) => boolean
}

// Backoff sequence between polls, capped at the last entry.
const POLL_BACKOFF_MS = [3000, 5000, 10000, 20000]

export function useApiData<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  options?: UseApiDataOptions<T>,
): ApiDataState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const pollWhile = options?.pollWhile
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffIndexRef = useRef(0)
  // Whether this hook has ever put data on screen. A ref, not the `data`
  // state: the closures below are created once per load and would forever see
  // the `data` of the render that created them.
  const hasDataRef = useRef(false)

  const load = useCallback(() => {
    let cancelled = false
    // Set once the session is known to be gone; from that point this hook is
    // inert - no reschedule, no state churn - because the document is on its
    // way to /login.
    let sessionExpired = false
    // Terminal for polling: `pollWhile` said stop, it threw, or the session
    // died. Distinct from `cancelled` (unmount / deps change), because a
    // terminal stop still leaves a mounted component rendering the last data.
    let stopped = false
    let listening = false
    // Issue order of the requests this load has started. Only the LAST one
    // issued may write state: a visibility flap can leave two fetches in
    // flight, and without this the slower (older) one wins by resolving last -
    // overwriting fresher data, and rescheduling polling off a state that has
    // already been superseded.
    let latestRequestId = 0

    const clearTimer = () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }

    const pollOnce = () => {
      if (cancelled || stopped || sessionExpired || document.hidden) return
      runRequest('poll')
    }

    const handleVisibilityChange = () => {
      if (document.hidden) {
        clearTimer()
        return
      }
      // Resuming visibility: fetch immediately and reset the backoff so a
      // backgrounded tab doesn't come back to a 20s-stale view. The timer is
      // cleared first so a refocus can never leave two of them running.
      backoffIndexRef.current = 0
      clearTimer()
      pollOnce()
    }

    // Polling is over for good. Everything this load installed goes with it -
    // in particular the visibilitychange listener, which used to outlive the
    // terminal state and fire one more request on every single tab refocus,
    // for as long as the tab stayed open.
    const stop = () => {
      stopped = true
      clearTimer()
      if (listening) {
        document.removeEventListener('visibilitychange', handleVisibilityChange)
        listening = false
      }
    }

    const scheduleNext = () => {
      if (cancelled || stopped) return
      const delay = POLL_BACKOFF_MS[Math.min(backoffIndexRef.current, POLL_BACKOFF_MS.length - 1)]
      backoffIndexRef.current += 1
      clearTimer()
      timerRef.current = setTimeout(pollOnce, delay)
    }

    // A `pollWhile` that throws is a CALLER bug, not a failed request, and the
    // two must not look the same to the user. Called bare inside the fetch's
    // `.then()` it landed in that request's `.catch`, so a predicate reading a
    // field the server had not sent yet rendered "request failed" over
    // perfectly good data - and on the initial load also silently disabled
    // polling, which is the exact symptom this hook exists to prevent. It is
    // reported where a bug belongs (the console) and otherwise treated like
    // `false`: stop, because a predicate that throws cannot be asked again.
    const shouldKeepPolling = (result: T): boolean => {
      if (!pollWhile) return false
      try {
        return pollWhile(result)
      } catch (err) {
        console.error('useApiData: pollWhile threw, stopping polling', err)
        return false
      }
    }

    // Silent poll path: unlike the initial load, a poll never touches
    // `loading` - that flag describes the first load only. Reusing the
    // loading-flipping path here would flash the page empty on every
    // interval (M-D pushed scan latency to minutes, so this runs a lot).
    const runRequest = (kind: 'initial' | 'poll') => {
      latestRequestId += 1
      const requestId = latestRequestId
      const isCurrent = () => !cancelled && !stopped && requestId === latestRequestId
      fetcher()
        .then((result) => {
          if (!isCurrent()) return
          hasDataRef.current = true
          setData(result)
          // Fresh data means whatever went wrong last time is over.
          setError(null)
          setPollError(null)
          if (shouldKeepPolling(result)) scheduleNext()
          else stop()
        })
        .catch((err: unknown) => {
          if (!isCurrent()) return
          // THE SEAM (polling x session expiry): a dead session is the one
          // failure that must NOT be retried. client.ts is already navigating
          // to /login; rescheduling here would leave the tab hammering 401 at
          // the 20s cap for as long as it stays open. No error text either -
          // the redirect is the UX, not "Error: Not authenticated".
          if (err instanceof SessionExpiredError) {
            sessionExpired = true
            stop()
            return
          }
          const message = err instanceof ApiError ? err.detail : 'request failed'
          // Which field this lands in depends on what the reader is left
          // looking at, not on which code path fetched it: a retry that fails
          // before anything has ever loaded (see below) is still "nothing to
          // show", not a stale-data notice.
          if (kind === 'initial' || !hasDataRef.current) setError(message)
          else setPollError(message)
          // A transient failure shouldn't permanently kill polling - keep
          // trying on the same backoff schedule. Reached from the INITIAL load
          // too: without it, opening a page during a two-second API blip
          // showed an error and then sat there forever, since two of the three
          // polling callers never destructure `reload` and the only way out
          // was to navigate away. Still gated on `pollWhile`, so a caller that
          // never asked for polling gets no timers at all.
          if (pollWhile) scheduleNext()
        })
        .finally(() => {
          // Staying in the loading state on an expired session is deliberate:
          // it keeps DataState showing "loading" until the redirect lands,
          // instead of dropping through to render children against null data.
          if (kind === 'initial' && !cancelled && !sessionExpired) setLoading(false)
        })
    }

    setLoading(true)
    setError(null)
    setPollError(null)
    backoffIndexRef.current = 0

    // Registered before the first request goes out, so `stop()` can never run
    // against a listener that is not attached yet.
    if (pollWhile) {
      listening = true
      document.addEventListener('visibilitychange', handleVisibilityChange)
    }

    runRequest('initial')

    return () => {
      cancelled = true
      stop()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generation, ...deps])

  useEffect(() => load(), [load])

  return { data, loading, error, pollError, reload: () => setGeneration((g) => g + 1) }
}
