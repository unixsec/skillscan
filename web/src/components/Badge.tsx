import { useI18n } from '../i18n/I18nContext'
import {
  ENGINE_HEALTH_BADGE_CLASS,
  engineHealthLabel,
  engineHealthState,
} from '../engineHealth'
import type { EngineObservation } from '../engineHealth'

const VERDICT_CLASS: Record<string, string> = {
  PASS: 'badge badge-pass',
  BLOCK: 'badge badge-block',
  REVIEW: 'badge badge-review',
}

export function VerdictBadge({ verdict }: { verdict: string | null }) {
  const { t } = useI18n()
  if (!verdict) return <span className="badge badge-neutral">{t('verdict.unknown')}</span>
  return (
    <span className={VERDICT_CLASS[verdict] ?? 'badge badge-neutral'}>
      {t(`verdict.${verdict}`)}
    </span>
  )
}

const SEVERITY_KEY: Record<number, string> = {
  0: 'severity.none',
  1: 'severity.low',
  2: 'severity.medium',
  3: 'severity.high',
  4: 'severity.critical',
}

const SEVERITY_CLASS: Record<number, string> = {
  0: 'badge badge-severity-none',
  1: 'badge badge-severity-low',
  2: 'badge badge-severity-medium',
  3: 'badge badge-severity-high',
  4: 'badge badge-severity-critical',
}

export function SeverityBadge({ severity }: { severity: number | null }) {
  const { t } = useI18n()
  if (severity === null) return <span className="badge badge-neutral">{t('verdict.unknown')}</span>
  return (
    <span className={SEVERITY_CLASS[severity] ?? 'badge badge-neutral'}>
      {t(SEVERITY_KEY[severity] ?? 'severity.none')}
    </span>
  )
}

export function BoolBadge({
  value,
  trueLabel,
  falseLabel,
}: {
  value: boolean
  trueLabel: string
  falseLabel: string
}) {
  return (
    <span className={value ? 'badge badge-block' : 'badge badge-pass'}>
      {value ? trueLabel : falseLabel}
    </span>
  )
}

// The ONE sanctioned way to put an engine's report_state/engine_status on
// screen (milestone C Task 10). `health === undefined` is a real, meaningful
// input - it renders "no observation in the retained window", which is neither
// a failure nor a success - so callers pass a lookup miss straight in rather
// than branching around this component and inventing their own dash.
//
// Takes an `EngineObservation`, not an `EngineHealth` (2026-07-30): the same
// badge now serves the admin window summary (via `windowObservation`) and a
// scan's per-engine coverage rows. A second badge for the second surface would
// have been a second chance to put `error` and `not_reported` on one colour,
// which is the distinction acceptance criterion 8 exists for.
export function EngineHealthBadge({ health }: { health: EngineObservation | undefined }) {
  const { t } = useI18n()
  return (
    <span className={ENGINE_HEALTH_BADGE_CLASS[engineHealthState(health)]}>
      {engineHealthLabel(t, health)}
    </span>
  )
}

export function ScoreBadge({ score, verdict }: { score: number | null; verdict: string | null }) {
  const { t } = useI18n()
  if (score === null) return <span className="badge badge-neutral">{t('verdict.unknown')}</span>
  // The score's band is fully determined by verdict by construction (2026-07-25
  // scoring design doc: security_score() always clamps into verdict's band) -
  // reuse VerdictBadge's color scheme instead of re-deriving a band from the
  // raw number here.
  return <span className={VERDICT_CLASS[verdict ?? ''] ?? 'badge badge-neutral'}>{score}</span>
}
