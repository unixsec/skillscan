import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './client'
import { useApiData } from './useApiData'

interface FakeStatus {
  status: string
}

// Flush pending promise microtasks (the fetcher's `.then/.catch/.finally`
// chain) without needing to advance the fake clock past a real timer.
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

function setHidden(hidden: boolean) {
  Object.defineProperty(document, 'hidden', { value: hidden, configurable: true })
}

// One tab hide + show, i.e. what the browser fires when the user switches away
// and comes back. The `show` half is what makes the hook fetch immediately.
async function hideAndShow() {
  setHidden(true)
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'))
  })
  setHidden(false)
  await act(async () => {
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(0)
  })
}

// A fetcher whose promises are settled BY THE TEST, one per call. Needed for
// anything about overlap - a `mockResolvedValueOnce` chain always settles in
// call order, which is the one ordering the interleaving bugs below cannot
// happen in.
function deferredFetcher() {
  const resolvers: ((value: FakeStatus) => void)[] = []
  const rejecters: ((reason: unknown) => void)[] = []
  const fetcher = vi.fn<() => Promise<FakeStatus>>(
    () =>
      new Promise<FakeStatus>((resolve, reject) => {
        resolvers.push(resolve)
        rejecters.push(reject)
      }),
  )
  return { fetcher, resolvers, rejecters }
}

describe('useApiData polling', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setHidden(false)
  })

  afterEach(() => {
    vi.useRealTimers()
    setHidden(false)
  })

  it('stops polling once pollWhile returns false', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockResolvedValueOnce({ status: 'queued' })
      .mockResolvedValueOnce({ status: 'queued' })
      .mockResolvedValueOnce({ status: 'done' })

    const { unmount } = renderHook(() =>
      useApiData(fetcher, [], { pollWhile: (d) => d.status !== 'done' }),
    )

    await flush()
    expect(fetcher).toHaveBeenCalledTimes(1)

    await advance(3000)
    expect(fetcher).toHaveBeenCalledTimes(2)

    await advance(5000)
    expect(fetcher).toHaveBeenCalledTimes(3) // status is now 'done' -> pollWhile stops it

    await advance(60000)
    expect(fetcher).toHaveBeenCalledTimes(3) // no further calls once terminal

    act(() => unmount())
  })

  it('backs off 3s -> 5s -> 10s -> 20s and caps', async () => {
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'queued' })

    const { unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    expect(fetcher).toHaveBeenCalledTimes(1)

    await advance(2999)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await advance(1)
    expect(fetcher).toHaveBeenCalledTimes(2) // +3s

    await advance(4999)
    expect(fetcher).toHaveBeenCalledTimes(2)
    await advance(1)
    expect(fetcher).toHaveBeenCalledTimes(3) // +5s

    await advance(9999)
    expect(fetcher).toHaveBeenCalledTimes(3)
    await advance(1)
    expect(fetcher).toHaveBeenCalledTimes(4) // +10s

    await advance(19999)
    expect(fetcher).toHaveBeenCalledTimes(4)
    await advance(1)
    expect(fetcher).toHaveBeenCalledTimes(5) // +20s

    // capped: the next interval is still 20s, not something longer
    await advance(19999)
    expect(fetcher).toHaveBeenCalledTimes(5)
    await advance(1)
    expect(fetcher).toHaveBeenCalledTimes(6) // +20s again (capped)

    act(() => unmount())
  })

  it('does not flip loading back to true while polling', async () => {
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'queued' })

    const { result, unmount } = renderHook(() =>
      useApiData(fetcher, [], { pollWhile: () => true }),
    )

    await flush()
    expect(result.current.loading).toBe(false)

    await advance(3000)
    expect(result.current.loading).toBe(false)
    expect(fetcher).toHaveBeenCalledTimes(2)

    act(() => unmount())
  })

  it('pauses while the document is hidden', async () => {
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'queued' })

    const { unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    expect(fetcher).toHaveBeenCalledTimes(1)

    setHidden(true)
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })

    await advance(60000)
    expect(fetcher).toHaveBeenCalledTimes(1) // no new calls while hidden

    act(() => unmount())
  })

  it('refetches immediately and resets the backoff when the tab comes back', async () => {
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'queued' })

    const { unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    // Walk the backoff up to the 10s step, so a reset is distinguishable from
    // "the next interval happened to be 3s anyway".
    await advance(3000)
    await advance(5000)
    expect(fetcher).toHaveBeenCalledTimes(3)

    await hideAndShow()
    expect(fetcher).toHaveBeenCalledTimes(4) // immediate, not after 10s

    await advance(2999)
    expect(fetcher).toHaveBeenCalledTimes(4)
    await advance(1)
    expect(fetcher).toHaveBeenCalledTimes(5) // backoff restarted at 3s

    act(() => unmount())
  })
})

// The two error fields mean different things and are NOT interchangeable:
// `error` is "there is nothing to show you", `pollError` is "what is on screen
// may be stale". DataState renders the first INSTEAD of the page.
describe('useApiData error reporting', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setHidden(false)
  })

  afterEach(() => {
    vi.useRealTimers()
    setHidden(false)
  })

  it('reports a failed FIRST load as `error`, with nothing on screen', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockRejectedValue(new ApiError(503, 'upstream unavailable'))

    const { result, unmount } = renderHook(() => useApiData(fetcher, []))

    await flush()
    expect(result.current.error).toBe('upstream unavailable')
    expect(result.current.pollError).toBeNull()
    expect(result.current.data).toBeNull()
    expect(result.current.loading).toBe(false)

    act(() => unmount())
  })

  it('leaves the data on screen when a POLL fails, instead of blanking the page', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockResolvedValueOnce({ status: 'running' })
      .mockRejectedValueOnce(new ApiError(503, 'upstream unavailable'))

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    await advance(3000)

    // The whole point of the second field: `error` is what DataState renders
    // INSTEAD of the children, so putting a transient poll failure there
    // replaces a fully rendered scan with one line of red text for 3 seconds.
    expect(result.current.error).toBeNull()
    expect(result.current.pollError).toBe('upstream unavailable')
    expect(result.current.data).toEqual({ status: 'running' })

    act(() => unmount())
  })

  it('clears a poll failure once a later poll succeeds', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockResolvedValueOnce({ status: 'running' })
      .mockRejectedValueOnce(new ApiError(503, 'upstream unavailable'))
      .mockResolvedValue({ status: 'scored' })

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    await advance(3000)
    expect(result.current.pollError).toBe('upstream unavailable')

    await advance(5000)
    // Fresh data means the failure is over. Clearing only on the initial load -
    // which is what this used to do - left the error rendering forever over
    // data that was provably fine, and neither polling page destructures
    // `reload`, so the user's only escape was to navigate away.
    expect(result.current.pollError).toBeNull()
    expect(result.current.error).toBeNull()
    expect(result.current.data).toEqual({ status: 'scored' })

    act(() => unmount())
  })

  it('clears a first-load error once the retry succeeds', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockRejectedValueOnce(new ApiError(503, 'upstream unavailable'))
      .mockResolvedValue({ status: 'running' })

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    expect(result.current.error).toBe('upstream unavailable')

    await advance(3000)
    expect(result.current.error).toBeNull()
    expect(result.current.data).toEqual({ status: 'running' })

    act(() => unmount())
  })

  it('keeps a retry that fails with nothing on screen in `error`, not `pollError`', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockRejectedValue(new ApiError(503, 'upstream unavailable'))

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    await advance(3000)
    expect(fetcher).toHaveBeenCalledTimes(2)
    // Nothing has EVER loaded, so this is still "nothing to show": the field
    // is chosen by what the reader is left looking at, not by which internal
    // code path issued the request.
    expect(result.current.error).toBe('upstream unavailable')
    expect(result.current.pollError).toBeNull()

    act(() => unmount())
  })

  // 里程碑 F review finding 2: the initial-load catch had no reschedule at all,
  // so a page opened during a two-second API blip showed an error and then sat
  // there forever - the exact state polling was added to eliminate.
  it('keeps retrying after a failed FIRST load', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockRejectedValueOnce(new ApiError(503, 'upstream unavailable'))
      .mockRejectedValueOnce(new ApiError(503, 'upstream unavailable'))
      .mockResolvedValue({ status: 'done' })

    const { result, unmount } = renderHook(() =>
      useApiData(fetcher, [], { pollWhile: (d) => d.status !== 'done' }),
    )

    await flush()
    expect(fetcher).toHaveBeenCalledTimes(1)

    await advance(3000)
    expect(fetcher).toHaveBeenCalledTimes(2) // retried on the normal backoff
    await advance(5000)
    expect(fetcher).toHaveBeenCalledTimes(3)

    // The retry succeeded with a terminal state, so the page recovered by
    // itself and polling stops.
    expect(result.current.error).toBeNull()
    expect(result.current.data).toEqual({ status: 'done' })
    await advance(60000)
    expect(fetcher).toHaveBeenCalledTimes(3)

    act(() => unmount())
  })

  it('installs no retry timer for a caller that never asked for polling', async () => {
    const fetcher = vi
      .fn<() => Promise<FakeStatus>>()
      .mockRejectedValue(new ApiError(503, 'upstream unavailable'))

    const { result, unmount } = renderHook(() => useApiData(fetcher, []))

    await flush()
    await advance(60000)
    // A page with no `pollWhile` opted out of background traffic entirely;
    // retrying it forever would be a behaviour it never asked for.
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(result.current.error).toBe('upstream unavailable')

    act(() => unmount())
  })
})

// 里程碑 F review finding 3: `pollWhile` ran bare inside the request's
// `.then()`, so anything it threw was caught by that request's `.catch` and
// shown to the user as a failed request.
describe('useApiData pollWhile contract', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setHidden(false)
  })

  afterEach(() => {
    vi.useRealTimers()
    setHidden(false)
  })

  it('does not report a throwing pollWhile as a request failure', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'running' })
    // The realistic shape of this bug: the predicate reaches into a field the
    // server has not sent yet.
    const pollWhile = (d: FakeStatus) =>
      (d as unknown as { items: { state: string }[] }).items.some((i) => i.state !== 'done')

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile }))

    await flush()
    // The request SUCCEEDED. A caller bug must not be dressed up as a server
    // outage, and must not blank a page whose data arrived intact.
    expect(result.current.error).toBeNull()
    expect(result.current.pollError).toBeNull()
    expect(result.current.data).toEqual({ status: 'running' })
    expect(result.current.loading).toBe(false)
    // Reported where a bug belongs.
    expect(consoleError).toHaveBeenCalled()

    consoleError.mockRestore()
    act(() => unmount())
  })

  it('stops polling when pollWhile throws, rather than looping on it', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'running' })
    let calls = 0
    const pollWhile = () => {
      calls += 1
      if (calls > 1) throw new TypeError('boom')
      return true
    }

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile }))

    await flush()
    await advance(3000) // second call -> throws
    expect(fetcher).toHaveBeenCalledTimes(2)

    // A predicate that throws cannot be asked again, so it is treated exactly
    // like `false` - and the data it threw on stays on screen.
    await advance(60000)
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(result.current.error).toBeNull()
    expect(result.current.pollError).toBeNull()
    expect(result.current.data).toEqual({ status: 'running' })

    consoleError.mockRestore()
    act(() => unmount())
  })
})

// 里程碑 F review finding 4: the visibilitychange listener outlived the
// terminal stop, and overlapping fetches could resolve out of order.
describe('useApiData lifecycle', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    setHidden(false)
  })

  afterEach(() => {
    vi.useRealTimers()
    setHidden(false)
  })

  it('detaches the visibilitychange listener once polling stops', async () => {
    const addSpy = vi.spyOn(document, 'addEventListener')
    const removeSpy = vi.spyOn(document, 'removeEventListener')
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'done' })

    const { unmount } = renderHook(() =>
      useApiData(fetcher, [], { pollWhile: (d) => d.status !== 'done' }),
    )

    await flush() // terminal on the very first load

    const added = addSpy.mock.calls.filter(([type]) => type === 'visibilitychange')
    const removed = removeSpy.mock.calls.filter(([type]) => type === 'visibilitychange')
    expect(added).toHaveLength(1)
    // Asserted BEFORE unmount on purpose: unmount removes the listener too, so
    // a test that looked afterwards would pass with the leak fully intact.
    expect(removed).toHaveLength(1)
    expect(removed[0][1]).toBe(added[0][1])

    addSpy.mockRestore()
    removeSpy.mockRestore()
    act(() => unmount())
  })

  it('does not fetch again on tab refocus after polling has stopped', async () => {
    const fetcher = vi.fn<() => Promise<FakeStatus>>().mockResolvedValue({ status: 'done' })

    const { unmount } = renderHook(() =>
      useApiData(fetcher, [], { pollWhile: (d) => d.status !== 'done' }),
    )

    await flush()
    expect(fetcher).toHaveBeenCalledTimes(1)

    // A settled scan detail page left open in a background tab: every switch
    // back to it used to cost one more request, for as long as the tab lived.
    await hideAndShow()
    await hideAndShow()
    await advance(60000)
    expect(fetcher).toHaveBeenCalledTimes(1)

    act(() => unmount())
  })

  it('never lets a stale in-flight response overwrite a newer one', async () => {
    const { fetcher, resolvers } = deferredFetcher()

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    expect(resolvers).toHaveLength(1)
    await act(async () => {
      resolvers[0]({ status: 'first' })
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current.data).toEqual({ status: 'first' })

    // Two refocuses in a row - the classic flap - leave two fetches in flight.
    await hideAndShow()
    await hideAndShow()
    expect(fetcher).toHaveBeenCalledTimes(3)

    // The NEWER request answers first...
    await act(async () => {
      resolvers[2]({ status: 'newest' })
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current.data).toEqual({ status: 'newest' })

    // ...and the older one the server was slow about answers second. Without
    // the issue-order guard it wins simply by resolving last, and the page
    // silently goes backwards in time.
    await act(async () => {
      resolvers[1]({ status: 'stale' })
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(result.current.data).toEqual({ status: 'newest' })

    act(() => unmount())
  })

  it('does not let a stale in-flight FAILURE overwrite a newer success', async () => {
    const { fetcher, resolvers, rejecters } = deferredFetcher()

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    await act(async () => {
      resolvers[0]({ status: 'first' })
      await vi.advanceTimersByTimeAsync(0)
    })

    await hideAndShow()
    await hideAndShow()
    expect(fetcher).toHaveBeenCalledTimes(3)

    await act(async () => {
      resolvers[2]({ status: 'newest' })
      await vi.advanceTimersByTimeAsync(0)
    })
    await act(async () => {
      rejecters[1](new ApiError(503, 'upstream unavailable'))
      await vi.advanceTimersByTimeAsync(0)
    })

    // A superseded request's failure is not news about the current state, and
    // must not put a stale-data notice over data that just arrived.
    expect(result.current.pollError).toBeNull()
    expect(result.current.error).toBeNull()
    expect(result.current.data).toEqual({ status: 'newest' })

    act(() => unmount())
  })

  it('drops a response that arrives after unmount, and schedules nothing', async () => {
    const { fetcher, resolvers } = deferredFetcher()

    const { result, unmount } = renderHook(() => useApiData(fetcher, [], { pollWhile: () => true }))

    await flush()
    expect(resolvers).toHaveLength(1)

    act(() => unmount())
    await act(async () => {
      resolvers[0]({ status: 'running' })
      await vi.advanceTimersByTimeAsync(0)
    })

    // An unmounted hook owns no timers: `pollWhile` would have said "keep
    // going" here, and honouring that would poll a page nobody is looking at.
    // Asserted on the timer itself rather than only on the call count, because
    // several later guards would also swallow the call and leave a scheduling
    // leak invisible.
    expect(vi.getTimerCount()).toBe(0)
    await advance(60000)
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(result.current.data).toBeNull()
  })
})
