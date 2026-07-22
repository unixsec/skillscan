import { useI18n } from '../i18n/I18nContext'

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
