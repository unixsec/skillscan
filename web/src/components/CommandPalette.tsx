import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { api } from '../api/client'
import { useI18n } from '../i18n/I18nContext'
import type { NavItem } from '../nav/navItems'
import type { InventorySkill, ScanSummary } from '../api/types'

interface PaletteEntry {
  id: string
  label: string
  sublabel?: string
  to: string
}

// Ranks a substring match by how early it starts: an exact-prefix match
// (typing "sc" for "scan-123") ranks above a match buried mid-string
// (matching "can" inside "scan-123" too, but less usefully). Returns -1 for
// no match at all, so callers can filter those out before sorting.
function scoreMatch(query: string, target: string): number {
  if (!query) return 0
  const idx = target.toLowerCase().indexOf(query.toLowerCase())
  if (idx === -1) return -1
  return idx === 0 ? 2 : 1
}

export function CommandPalette({ items }: { items: NavItem[] }) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [skills, setSkills] = useState<InventorySkill[]>([])
  const inputRef = useRef<HTMLInputElement>(null)

  const hasScans = items.some((item) => item.to === '/scans')
  const hasInventory = items.some((item) => item.to === '/inventory')

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      } else if (e.key === 'Escape') {
        setOpen(false)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [])

  useEffect(() => {
    if (!open) return
    setQuery('')
    inputRef.current?.focus()
    if (hasScans) {
      api
        .get<{ items: ScanSummary[] }>('/v1/scans')
        .then((r) => setScans(r.items))
        .catch(() => setScans([]))
    }
    if (hasInventory) {
      api
        .get<{ skills: InventorySkill[] }>('/v1/inventory')
        .then((r) => setSkills(r.skills))
        .catch(() => setSkills([]))
    }
  }, [open, hasScans, hasInventory])

  const entries = useMemo<PaletteEntry[]>(() => {
    const navEntries = items.map((item) => ({ id: `nav:${item.to}`, label: t(item.labelKey), to: item.to }))
    const scanEntries = scans.map((s) => ({
      id: `scan:${s.scan_id}`,
      label: s.scan_id,
      sublabel: `${s.submitter} · ${s.state}`,
      to: `/scans/${s.scan_id}`,
    }))
    const skillEntries = skills.map((s) => ({
      id: `skill:${s.skill_id}`,
      label: s.skill_id,
      sublabel: s.source,
      to: `/inventory/${s.skill_id}`,
    }))
    return [...navEntries, ...scanEntries, ...skillEntries]
  }, [items, scans, skills, t])

  const results = useMemo(() => {
    if (!query.trim()) return entries.filter((e) => e.id.startsWith('nav:'))
    return entries
      .map((entry) => ({
        entry,
        score: Math.max(scoreMatch(query, entry.label), scoreMatch(query, entry.sublabel ?? '')),
      }))
      .filter((r) => r.score >= 0)
      .sort((a, b) => b.score - a.score)
      .map((r) => r.entry)
      .slice(0, 20)
  }, [entries, query])

  if (!open) return null

  function go(to: string) {
    setOpen(false)
    navigate(to)
  }

  return (
    <div
      className="palette-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) setOpen(false)
      }}
    >
      <div className="palette-panel" role="dialog" aria-modal="true" aria-label={t('palette.title')}>
        <div className="palette-input-row">
          <Search size={16} aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('palette.placeholder')}
            className="palette-input"
          />
        </div>
        <div className="palette-results">
          {results.length === 0 && <div className="palette-empty">{t('palette.noResults')}</div>}
          {results.map((entry) => (
            <button key={entry.id} type="button" className="palette-result" onClick={() => go(entry.to)}>
              <span className="palette-result-label">{entry.label}</span>
              {entry.sublabel && <span className="palette-result-sublabel">{entry.sublabel}</span>}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
