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
    let detail = response.statusText
    try {
      const errorBody: unknown = await response.json()
      if (errorBody && typeof errorBody === 'object' && 'detail' in errorBody) {
        detail = String((errorBody as { detail: unknown }).detail)
      }
    } catch {
      // response body wasn't JSON - keep statusText
    }
    throw new ApiError(response.status, detail)
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
    let detail = response.statusText
    try {
      const errorBody: unknown = await response.json()
      if (errorBody && typeof errorBody === 'object' && 'detail' in errorBody) {
        detail = String((errorBody as { detail: unknown }).detail)
      }
    } catch {
      // non-JSON error body - keep statusText
    }
    throw new ApiError(response.status, detail)
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
