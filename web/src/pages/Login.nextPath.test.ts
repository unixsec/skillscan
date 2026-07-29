import { describe, expect, it } from 'vitest'
import { safeNextPath } from './Login'

// `next` is written by client.ts on a 401, but it arrives through the URL and
// is therefore attacker-controllable: anyone can mail a /login?next=... link.
// Honouring an off-site value would make the console's own login page a
// credible phishing hop.
describe('safeNextPath', () => {
  it('returns a same-origin path unchanged, query included', () => {
    expect(safeNextPath('/scans?page=2&state=queued')).toBe('/scans?page=2&state=queued')
    expect(safeNextPath('/inventory/skill-123')).toBe('/inventory/skill-123')
  })

  it('falls back to the dashboard when there is no next', () => {
    expect(safeNextPath(null)).toBe('/')
    expect(safeNextPath('')).toBe('/')
  })

  it.each([
    'https://evil.example/steal',
    '//evil.example/steal',
    '/\\evil.example/steal',
    'javascript:alert(1)',
    'scans',
  ])('refuses an off-site or relative target (%s)', (raw) => {
    expect(safeNextPath(raw)).toBe('/')
  })
})
