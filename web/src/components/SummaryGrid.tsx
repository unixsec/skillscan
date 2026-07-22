import { useI18n } from '../i18n/I18nContext'
import { Sparkline } from './Sparkline'

interface Stat {
  key: string
  label: string
  value: string
  accent?: string
  trend?: number[]
}

// Verdict sub-stats get the same semantic colors their badges use elsewhere,
// so "通过 / 待复核 / 不通过" cards read consistently with the rest of the app.
const VERDICT_ACCENT: Record<string, string> = {
  PASS: 'var(--ok)',
  REVIEW: 'var(--medium)',
  BLOCK: 'var(--critical)',
}

function labelFor(key: string, t: (k: string) => string, fallback: string): string {
  const translated = t(key)
  return translated === key ? fallback : translated
}

// Nested breakdown OBJECTS (e.g. verdict_counts: {PASS, REVIEW, BLOCK}) are
// flattened into stat cards at the SAME level as scalar stats like
// total_verdicts - one card per sub-entry, never a joined string crammed
// into a single card. `trends` is an optional key->series lookup (same key
// shape this function produces: "verdict_counts.PASS" for sub-entries, the
// plain key for scalars) - callers that don't have time-series data simply
// omit it, and no stat gets a sparkline.
//
// ARRAYS (e.g. engine_coverage's required_floor/currently_disabled: string[])
// are a DIFFERENT shape and must not go through the same per-entry split:
// `typeof [] === 'object'` is true in JS, so before this fix an array fell
// into the nested-object branch and Object.entries() indexed it by position
// - "required_floor: ['bandit', 'osv-scanner']" rendered as two bogus cards
// labeled "0"/"1" instead of one readable list (2026-07-14, item #10). Each
// array becomes a single card whose value is the joined list.
function flatten(
  summary: Record<string, unknown>,
  t: (k: string) => string,
  trends?: Record<string, number[]>,
): Stat[] {
  const stats: Stat[] = []
  for (const [key, value] of Object.entries(summary)) {
    if (Array.isArray(value)) {
      stats.push({
        key,
        label: labelFor(`summary.${key}`, t, key.replaceAll('_', ' ')),
        value: value.length > 0 ? value.map(String).join(', ') : '—',
      })
      continue
    }
    if (value !== null && typeof value === 'object') {
      for (const [subKey, subValue] of Object.entries(value as Record<string, unknown>)) {
        const flatKey = `${key}.${subKey}`
        stats.push({
          key: flatKey,
          label: labelFor(`verdict.${subKey}`, t, labelFor(`summary.${flatKey}`, t, subKey)),
          value: String(subValue),
          accent: VERDICT_ACCENT[subKey],
          trend: trends?.[flatKey],
        })
      }
      continue
    }
    stats.push({
      key,
      label: labelFor(`summary.${key}`, t, key.replaceAll('_', ' ')),
      value: String(value),
      trend: trends?.[key],
    })
  }
  return stats
}

export function SummaryGrid({
  summary,
  trends,
}: {
  summary: Record<string, unknown>
  trends?: Record<string, number[]>
}) {
  const { t } = useI18n()
  return (
    <div className="summary-grid">
      {flatten(summary, t, trends).map((stat) => (
        <div className="summary-stat" key={stat.key}>
          <div className="value" style={stat.accent ? { color: stat.accent } : undefined}>
            {stat.value}
          </div>
          {stat.trend && stat.trend.length >= 3 && (
            <Sparkline values={stat.trend} stroke={stat.accent ?? 'var(--accent)'} />
          )}
          <div className="label">{stat.label}</div>
        </div>
      ))}
    </div>
  )
}
