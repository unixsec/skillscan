import { useCallback, useEffect, useState } from 'react'
import { ApiError } from './client'

interface ApiDataState<T> {
  data: T | null
  loading: boolean
  error: string | null
  reload: () => void
}

export function useApiData<T>(fetcher: () => Promise<T>, deps: unknown[] = []): ApiDataState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const load = useCallback(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    fetcher()
      .then((result) => {
        if (!cancelled) setData(result)
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.detail : 'request failed')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generation, ...deps])

  useEffect(() => load(), [load])

  return { data, loading, error, reload: () => setGeneration((g) => g + 1) }
}
