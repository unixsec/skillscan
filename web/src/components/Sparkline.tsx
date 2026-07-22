interface SparklineProps {
  values: number[]
  width?: number
  height?: number
  stroke?: string
}

export function Sparkline({ values, width = 64, height = 20, stroke = 'var(--accent)' }: SparklineProps) {
  // A 2-point series is always a single straight line regardless of scaling -
  // with sparse real data (e.g. a big one-day batch import) that reads as a
  // stray diagonal under the number rather than a trend. Require at least 3
  // points before rendering anything.
  if (values.length < 3) return null
  const max = Math.max(...values)
  // Relative-range baseline, not zero-anchored: a sparkline has no visible
  // axis, so its job is to show the SHAPE of recent variation, not absolute
  // magnitude - zero-anchoring compresses that shape flat for series that
  // never approach zero (e.g. [950,1000,1050]).
  const min = Math.min(...values)
  const range = max - min || 1
  const stepX = width / (values.length - 1)
  const points = values
    .map((v, i) => `${i * stepX},${height - ((v - min) / range) * height}`)
    .join(' ')
  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="sparkline"
      aria-hidden="true"
    >
      <polyline
        points={points}
        fill="none"
        stroke={stroke}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
