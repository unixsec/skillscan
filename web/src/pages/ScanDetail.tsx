import { useParams } from 'react-router-dom'
import { api } from '../api/client'
import { useApiData } from '../api/useApiData'
import { DataState } from '../components/DataState'
import { EngineHealthBadge, ScoreBadge, SeverityBadge, VerdictBadge } from '../components/Badge'
import { useI18n } from '../i18n/I18nContext'
import { reasonLabel } from '../i18n/reasons'
import { scanStateLabel, TERMINAL_SCAN_STATES } from '../scanState'
import {
  coverageObservation,
  engineDurationLabel,
  notReportedAttributionHint,
  notReportedAttributionLabel,
} from '../engineHealth'
import type {
  Finding,
  ScanDetail,
  ScanEngineCoverage,
  ScanEngineCoverageEntry,
  SubmitterSource,
} from '../api/types'

// The 8 detection categories (SRS §3.3 "8类61项") - shown in a FIXED, complete
// order regardless of which ones actually have findings, so the by-category
// view is a full situational overview ("态势"), not just a list of hits.
const ALL_CATEGORIES = [
  'instruction',
  'code',
  'data_credential',
  'network_intel',
  'permission',
  'file_package',
  'supply_chain',
  'bundled_component',
]

interface ModuleRow {
  key: string
  label: string
  version?: string
  count: number
  maxSeverity: number | null
  // 2026-07-30: this engine's evidence is NOT in the verdict, so its `count: 0`
  // is an absence of evidence and not an absence of findings. Only ever set on
  // the by-ENGINE rows - a category has no report state.
  noEvidence?: boolean
}

function maxSeverityOf(findings: Finding[]): number | null {
  if (findings.length === 0) return null
  return Math.max(...findings.map((f) => f.severity))
}

// A dictionary miss resolves to the key itself (see makeTranslate in
// i18n/translations.ts) - fall back to the RAW wire value in that case, so an
// engine/tier/signal this build has never heard of shows as "osv-scanner",
// not as "engine.osv-scanner" and never as blank.
function translatedOr(t: (key: string) => string, key: string, raw: string): string {
  const translated = t(key)
  return translated === key ? raw : translated
}

function engineLabel(name: string, t: (key: string) => string): string {
  return translatedOr(t, `engine.${name}`, name)
}

// The fatal-trifecta signals (INV-4; libs/skillscan_core/models.py's
// TrifectaSignal) are recorded PER FINDING but describe the SCAN: it is their
// co-occurrence ACROSS the package - not inside a single finding - that forces
// CRITICAL (scoring.aggregate's ALL_TRIFECTA_SIGNALS.issubset). So they are
// unioned here and shown once next to the verdict, rather than repeated in
// every findings row where they would read as a per-row property.
export function scanTrifectaSignals(findings: Finding[]): string[] {
  const signals = new Set<string>()
  for (const finding of findings) {
    for (const signal of finding.trifecta_signals ?? []) signals.add(signal)
  }
  return [...signals].sort()
}

// Engine names whose findings are absent from this verdict. Read off the
// server's coverage answer, never re-derived from `provenance` - a timed-out
// engine HAS a provenance triple (`unavailable_engine_result` fabricates one so
// the gate can fail closed), which is precisely why the by-engine table below
// used to score it green "PASS" on zero findings.
//
// `not_applicable` is included: an engine this deployment does not run has no
// findings in the verdict either, and labelling that row "PASS" is the same
// false statement. The COVERAGE section above is where the two classes are
// distinguished; here they share one consequence.
export function noEvidenceEngineNames(data: ScanDetail): Set<string> {
  return new Set(data.engine_coverage.engines.map((e) => e.name))
}

function byEngine(data: ScanDetail, t: (key: string) => string): ModuleRow[] {
  const noEvidence = noEvidenceEngineNames(data)
  const engines = new Map<string, string>() // name -> version
  for (const [name, version] of data.provenance) {
    engines.set(name, version)
  }
  // a finding's source_engine might not appear in provenance (e.g. an
  // in-house detector not modeled as a vendored "engine") - include those too
  // so no real finding is silently dropped from this module view.
  for (const f of data.findings) {
    if (!engines.has(f.source_engine)) engines.set(f.source_engine, '')
  }
  return [...engines.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, version]) => {
      const findings = data.findings.filter((f) => f.source_engine === name)
      return {
        key: name,
        label: engineLabel(name, t),
        version,
        count: findings.length,
        maxSeverity: maxSeverityOf(findings),
        noEvidence: noEvidence.has(name),
      }
    })
}

function byCategory(data: ScanDetail, t: (key: string) => string): ModuleRow[] {
  return ALL_CATEGORIES.map((category) => {
    const findings = data.findings.filter((f) => f.category === category)
    return {
      key: category,
      label: t(`category.${category}`),
      count: findings.length,
      maxSeverity: maxSeverityOf(findings),
    }
  })
}

function ModuleTable({ rows, moduleLabel, versionLabel }: { rows: ModuleRow[]; moduleLabel: string; versionLabel?: string }) {
  const { t } = useI18n()
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{moduleLabel}</th>
            {versionLabel && <th>{versionLabel}</th>}
            <th>{t('scanDetail.colFindingCount')}</th>
            <th>{t('scanDetail.colMaxSeverity')}</th>
            <th>{t('scanDetail.colStatus')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td>{row.label}</td>
              {versionLabel && (
                <td>
                  <code>{row.version || '—'}</code>
                </td>
              )}
              <td>{row.count}</td>
              <td>
                <SeverityBadge severity={row.maxSeverity} />
              </td>
              <td>
                {/* THREE outcomes, not two (2026-07-30). "0 findings" from an
                    engine that never delivered is not a pass - it is no
                    evidence, and this cell rendered it green for as long as the
                    table has existed, directly beside a coverage warning saying
                    the opposite. `provenance` cannot tell them apart because
                    `unavailable_engine_result` fabricates a triple so the gate
                    can fail closed; only the coverage read can. */}
                {row.noEvidence ? (
                  <span className="badge badge-review">{t('scanDetail.statusNoEvidence')}</span>
                ) : (
                  <span className={row.count === 0 ? 'badge badge-pass' : 'badge badge-block'}>
                    {row.count === 0 ? t('scanDetail.statusPass') : t('scanDetail.statusFail')}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// The tier THIS viewer asked for, and the tier the verdict was actually reached
// at. 里程碑 F Task 14 made these two genuinely different backend facts - the
// viewer's own `scan_submitter.requested_trust_tier` and `ScanJob.trust_tier` -
// so this line can finally fire. Before that they were one column read twice
// and the "they differ" branch was unreachable no matter what the data said.
//
// They diverge when single-flight dedup hands a later submitter a verdict that
// was adjudicated for someone else and is never redone. The BLOCK threshold is
// tier-dependent (GatePolicy.block_threshold), so this changes what the verdict
// on screen actually means.
//
// The DIRECTION comes from the server (`tier_direction`), computed from the gate
// policy's real thresholds. It is deliberately not re-derived here from the tier
// names: which tier is stricter is a property of policies/gate/v1.yaml's
// tier_block_overrides, not of the strings, and a console that guessed could
// label the dangerous direction as the safe one.
function TrustTierLine({
  trustTier,
  judgedAtTier,
  tierDirection,
  tierDirectionBasis,
}: {
  trustTier: string | null
  judgedAtTier: string | null
  tierDirection: ScanDetail['tier_direction']
  tierDirectionBasis: ScanDetail['tier_direction_basis']
}) {
  const { t } = useI18n()
  // Both null means the scan records no tier at all (legacy rows - see
  // ScanJob.trust_tier); the honest rendering of "not recorded" is absence.
  if (trustTier === null && judgedAtTier === null) return null
  const mismatch = trustTier !== judgedAtTier
  // Only 'looser' is a warning: the verdict was reached under a MORE permissive
  // ruleset than this viewer asked for, so a finding that should have blocked
  // for them can read PASS. 'stricter' over-blocks, which is worth saying but is
  // not a hole; 'equivalent' means the policy treats the two names the same.
  // Styling every difference as an error would bury the one that matters.
  const dangerous = tierDirection === 'looser'
  const tierLabel = (tier: string | null) =>
    tier === null ? '—' : translatedOr(t, `trustTier.${tier}`, tier)
  const mismatchMessage =
    tierDirection === 'looser'
      ? t('scanDetail.tierMismatchLooser')
      : tierDirection === 'stricter'
        ? t('scanDetail.tierMismatchStricter')
        : tierDirection === 'equivalent'
          ? t('scanDetail.tierMismatchEquivalent')
          : t('scanDetail.tierMismatch')
  return (
    <p className={dangerous ? 'error' : 'hint'}>
      {t('scanDetail.trustTier')}{' '}
      <span className={mismatch ? 'badge badge-review' : 'badge badge-neutral'}>
        {tierLabel(trustTier)}
      </span>
      {' · '}
      {t('scanDetail.judgedAtTier')}{' '}
      <span className={dangerous ? 'badge badge-block' : 'badge badge-neutral'}>
        {tierLabel(judgedAtTier)}
      </span>
      {mismatch && <> — {mismatchMessage}</>}
      {/* The caveat, and only when it is one. `tier_direction` is computed from
          the policy the server has loaded NOW, while the verdict was signed
          under whichever policy was loaded then - so on 'current_policy' the
          sentence above describes today's thresholds, not necessarily the
          adjudication that happened. Printing this on every scan would train
          readers to skip it, so it is shown only when the comparison really is
          retrospective. The server does not reconstruct the historical policy
          to remove the caveat: only the verdict's policy_version survives, not
          the thresholds it carried. */}
      {mismatch && tierDirectionBasis === 'current_policy' && (
        <> {t('scanDetail.tierDirectionCurrentPolicy')}</>
      )}
    </p>
  )
}

// Does THIS submitter's requested tier actually diverge from the tier the
// verdict was reached at?
//
// The comparison that matters is the policy's, not the strings'. The server
// makes exactly one such comparison per response - `trust_tier` (the tier THIS
// viewer asked for) against `judged_at_tier` - and publishes the answer as
// `tier_direction`, computed by `gate.policy.tier_direction` from
// `GatePolicy.block_threshold` and its `tier_block_overrides`. That answer is a
// property of the PAIR of tiers, so it transfers verbatim to any other
// submitter who asked for the same tier.
//
// 'equivalent' is the case this exists for: two tier names the current policy
// blocks at the identical threshold. The headline says so in words ("this
// verdict is unaffected"); a bare name comparison down here flagged the same
// pair as a divergence with no explanation at all, so the list contradicted the
// paragraph directly above it - and every false flag makes the one that matters
// easier to skip.
//
// For a tier the server never compared, the honest answer is `unknown`: the
// tier is still shown (they did ask for something else) but no claim is made
// about what it means, because deriving one from tier NAMES is precisely what
// Task 18 moved into `gate.policy` to stop - strictness lives in
// `tier_block_overrides`, and a name-order guess can label the dangerous
// direction safe.
type SubmitterTierDivergence = NonNullable<ScanDetail['tier_direction']> | 'unknown'

export function submitterTierDivergence(
  detail: Pick<ScanDetail, 'trust_tier' | 'judged_at_tier' | 'tier_direction'>,
  requestedTier: string,
): SubmitterTierDivergence | null {
  // The tier the verdict was actually reached at: nothing diverged.
  if (requestedTier === detail.judged_at_tier) return null
  if (requestedTier === detail.trust_tier && detail.tier_direction !== null) {
    return detail.tier_direction
  }
  // `tier_direction === null` on a pair whose names differ means the server
  // could NOT compare them (a tier the policy does not define). That is not a
  // licence to suppress the row - it is the reason to make no claim about it.
  return 'unknown'
}

// Everyone this scan belongs to, with the channel each of them came through.
//
// `submitter_sources` is the authoritative per-name attribution (one row per
// ScanSubmitterRow). The two fallbacks below exist for rows written before the
// backend grew those fields and are never used to invent data: a submitter with
// no recorded channel keeps `source: null` and simply renders without one.
function submitterEntries(detail: ScanDetail): SubmitterSource[] {
  if (detail.submitter_sources?.length) return detail.submitter_sources
  const names = detail.submitters?.length
    ? detail.submitters
    : detail.submitter
      ? [detail.submitter]
      : []
  return names.map((submitter) => ({ submitter, source: null, requested_trust_tier: null }))
}

// This used to be a single-value "submitter" tile fed by `ScanJob.submitter` -
// the FIRST person to submit this content, not the only one. Submissions of
// byte-identical content collapse onto one scan_job (ScanSubmitterRow), so on a
// deduplicated scan that one name is a STRANGER'S to everyone who submitted
// afterwards: they opened their own scan and were shown somebody else as its
// owner. All authorized submitters are listed now.
function SubmitterLine({ detail }: { detail: ScanDetail }) {
  const { t } = useI18n()
  const entries = submitterEntries(detail)
  // No submitter recorded at all - absence is the honest rendering, the same
  // choice TrustTierLine makes for an unrecorded tier.
  if (entries.length === 0) return null
  return (
    <p className="hint">
      {t('scanDetail.submitters')}{' '}
      {entries.map((entry) => {
        // 里程碑 F Task 14: shown only when this name asked for a tier the
        // verdict was NOT reached at. Printing it on every row would repeat the
        // judged tier N times and bury the one row that diverges - and a
        // divergence here is what an approver has to see, since the tier line
        // above only covers the tier THEY themselves requested. `null` (no
        // request on record) prints nothing rather than a guess, and so does a
        // difference the gate policy itself treats as no difference (see
        // `submitterTierDivergence` - this used to be a bare `!==` on the tier
        // names, which flagged exactly the pairs the headline explains away).
        const divergence =
          entry.requested_trust_tier === null
            ? null
            : submitterTierDivergence(detail, entry.requested_trust_tier)
        return (
          <span
            key={entry.submitter}
            className="badge badge-neutral"
            style={{ marginRight: '0.35rem' }}
          >
            {entry.submitter}
            {entry.source !== null &&
              ` · ${translatedOr(t, `submissionChannel.${entry.source}`, entry.source)}`}
            {divergence !== null &&
              divergence !== 'equivalent' &&
              entry.requested_trust_tier !== null &&
              ` · ${t('scanDetail.submitterRequestedTier', {
                tier: translatedOr(
                  t,
                  `trustTier.${entry.requested_trust_tier}`,
                  entry.requested_trust_tier,
                ),
              })}`}
          </span>
        )
      })}
      {entries.length > 1 && <> {t('scanDetail.dedupSubmittersHint')}</>}
    </p>
  )
}

// Scan-level signals behind the verdict: the hard-gate rules that fired
// (unwaivable, INV-3) and the fatal-trifecta signals seen across the package
// (INV-4). Both were already being fetched and thrown away.
function ScanSignals({
  hardGateHits,
  trifectaSignals,
}: {
  hardGateHits: string[]
  trifectaSignals: string[]
}) {
  const { t } = useI18n()
  // Nothing to report -> report nothing. An empty "hard-gate hits: —" label is
  // noise that reads like a result and pushes the real content down the page.
  if (hardGateHits.length === 0 && trifectaSignals.length === 0) return null
  return (
    <>
      <h2>{t('scanDetail.signals')}</h2>
      {hardGateHits.length > 0 && (
        <p>
          <span className="hint">{t('scanDetail.hardGateHits')}</span>{' '}
          {hardGateHits.map((rule) => (
            <span key={rule} className="badge badge-block" style={{ marginRight: '0.35rem' }}>
              {rule}
            </span>
          ))}
        </p>
      )}
      {trifectaSignals.length > 0 && (
        <>
          <p>
            <span className="hint">{t('scanDetail.trifectaSignals')}</span>{' '}
            {trifectaSignals.map((signal) => (
              <span
                key={signal}
                className="badge badge-review"
                style={{ marginRight: '0.35rem' }}
              >
                {translatedOr(t, `trifecta.${signal}`, signal)}
              </span>
            ))}
          </p>
          {/* States the RULE, not a derived claim: whether this particular
              scan's trifecta is complete is decided server-side on the
              pre-cap, pre-dedup finding set (scoring.aggregate), which is not
              what this list is built from - re-deriving it here could
              contradict the verdict above. */}
          <p className="hint">{t('scanDetail.trifectaHint')}</p>
        </>
      )}
    </>
  )
}

// WHICH engines' evidence is missing from this verdict (2026-07-30).
//
// The page already showed `requiredEngineWarning` off `required_ok`, and that
// covers the FLOOR only - `GatePolicy.required_engines`, which fails closed. A
// 290-scan real-world run confirmed that path works. Every OTHER engine fails
// OPEN: it does not deliver, its findings are discarded, and the verdict is
// computed on what remains. On that run, complete-evidence scans came back 60%
// REVIEW and incomplete ones 29% - the verdict got MORE permissive as evidence
// shrank, and this page said nothing about it.
//
// It also directly contradicted itself: the by-engine table below builds its
// rows from `provenance`, which carries a triple for a timed-out engine too, and
// scored it green "PASS" on 0 findings. `missingEngineNames` is threaded into
// that table for exactly this reason.
//
// TWO CLASSES, rendered differently, and that distinction is the whole design:
//   'missing'        - expected here, did not deliver, no readable cause. Red.
//   'not_applicable' - this deployment does not run the engine at all.
//                      `aig-mcp-scan` is in this class on 100% of scans of any
//                      deployment with no LLM endpoint. Rendering it as a fault
//                      on every scan forever would train readers to skip this
//                      whole section, which is worse than not having it.
function EngineCoverage({ coverage }: { coverage: ScanEngineCoverage }) {
  const { t } = useI18n()
  // No per-engine record at all: a dead-lettered scan, one past the health
  // table's retention window, or one scored before that table existed. Said out
  // loud rather than rendered as silence, because silence here is
  // indistinguishable from "every engine reported".
  if (coverage.complete === null) {
    return (
      <>
        <h2>{t('scanDetail.coverage')}</h2>
        <p className="hint">{t('scanDetail.coverageUnrecorded')}</p>
      </>
    )
  }
  const missing = coverage.engines.filter((e) => e.coverage === 'missing')
  const notApplicable = coverage.engines.filter((e) => e.coverage === 'not_applicable')
  return (
    <>
      <h2>{t('scanDetail.coverage')}</h2>
      <p className={missing.length > 0 ? 'error' : 'hint'}>
        {t('scanDetail.coverageCount', {
          reported: coverage.reported,
          expected: coverage.expected,
        })}
        {missing.length > 0 && <> {t('scanDetail.coverageIncompleteHint')}</>}
      </p>
      {missing.length > 0 && <CoverageRows entries={missing} />}
      {notApplicable.length > 0 && (
        <>
          {/* Not a fault, and styled as the quietest thing on the page. Still
              SHOWN: `expected` was reduced by exactly these engines, and a
              coverage count whose denominator shrank for unstated reasons is
              not falsifiable. */}
          <p className="hint">
            {t('scanDetail.coverageNotApplicable', { count: notApplicable.length })}
          </p>
          <CoverageRows entries={notApplicable} />
        </>
      )}
      {/* The caveat that has to travel with the count, and the same one the
          admin engine console prints: `expected` excludes engines TODAY'S
          configuration says this deployment does not run, and nothing recorded
          the configuration this scan actually ran under. Shown only when
          something was actually excluded on that basis - printing it on every
          scan is how a caveat becomes invisible. */}
      {notApplicable.length > 0 && coverage.basis === 'current_config' && (
        <p className="hint">{t('scanDetail.coverageBasisCurrentConfig')}</p>
      )}
    </>
  )
}

function CoverageRows({ entries }: { entries: ScanEngineCoverageEntry[] }) {
  const { t } = useI18n()
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('scanDetail.colModule')}</th>
            <th>{t('scanDetail.colStatus')}</th>
            <th>{t('adminEngines.colLastDuration')}</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => {
            // `coverageObservation` narrows the row to the three fields
            // engineHealth.ts reads, so this page uses the SAME six-state
            // machine, the same badge colours and the same three duration
            // states as the admin engine console - `error` and `not_reported`
            // cannot land on one colour here either.
            const observation = coverageObservation(entry)
            const attribution = notReportedAttributionLabel(t, observation)
            return (
              <tr key={entry.name}>
                <td>{engineLabel(entry.name, t)}</td>
                <td>
                  <EngineHealthBadge health={observation} />
                  {attribution && (
                    <div className="hint" title={notReportedAttributionHint(t, observation)}>
                      {attribution}
                    </div>
                  )}
                </td>
                <td>{engineDurationLabel(t, observation)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function ScanDetailContent({ scanId }: { scanId: string }) {
  const { t } = useI18n()
  const { data, loading, error, pollError } = useApiData<ScanDetail>(
    () => api.get(`/v1/scans/${scanId}`),
    [scanId],
    { pollWhile: (d) => !TERMINAL_SCAN_STATES.has(d.state) },
  )
  // required_ok is null EXCLUSIVELY when no ScanResultRow exists at all (GET
  // /v1/scans/{id}'s own fallback) - the poison-pill/dead-letter path
  // (orchestration.service._dead_letter_and_decide) records a real, signed
  // verdict WITHOUT ever aggregating real engine findings, since there's
  // genuinely nothing to aggregate. Rendering the by-engine/by-category
  // breakdown and an empty findings list in that case showed everything as
  // "0 findings = PASS", directly contradicting the BLOCK verdict sitting
  // right above it - found live via scan 87ad9d0e-d430-40f1-8ffd-50219cba4465.
  const neverScored = data != null && data.required_ok === null && data.verdict !== null

  return (
    <DataState loading={loading} error={error}>
      {data && (
        <>
          {/* A background poll failed while this page was up. Said out loud
              rather than swallowed - on a scan that has not settled yet, the
              state/verdict below are the whole point and the reader has to
              know they may have stopped advancing - but NOT through
              `DataState`, which would replace the entire rendered scan with
              one line of red text until the next poll succeeds. */}
          {pollError !== null && (
            <p className="hint">{t('common.refreshFailed', { message: pollError })}</p>
          )}

          <div className="summary-grid">
            <div className="summary-stat">
              <div className="value">{scanStateLabel(t, data.state)}</div>
              <div className="label">{t('scanDetail.state')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">
                <VerdictBadge verdict={data.verdict} />
              </div>
              <div className="label">{t('scanDetail.verdict')}</div>
            </div>
            <div className="summary-stat">
              <div className="value">
                <ScoreBadge score={data.score} verdict={data.verdict} />
              </div>
              <div className="label">{t('scanDetail.score')}</div>
            </div>
            {/* The server's own plain answer to "may I use this?" - it is
                derived from the verdict (verdict == PASS, see gateway/
                router.py's get_scan), but a reader should not have to know
                that PASS is the only safe verdict to get the answer. `null`
                means no verdict exists yet and is never guessed at. */}
            <div className="summary-stat">
              <div className="value">
                {data.is_safe === null ? (
                  <span className="badge badge-neutral">{t('verdict.unknown')}</span>
                ) : (
                  <span className={data.is_safe ? 'badge badge-pass' : 'badge badge-block'}>
                    {data.is_safe ? t('scanDetail.isSafeYes') : t('scanDetail.isSafeNo')}
                  </span>
                )}
              </div>
              <div className="label">{t('scanDetail.isSafe')}</div>
            </div>
          </div>

          <SubmitterLine detail={data} />

          <TrustTierLine
            trustTier={data.trust_tier}
            judgedAtTier={data.judged_at_tier}
            tierDirection={data.tier_direction ?? null}
            tierDirectionBasis={data.tier_direction_basis ?? null}
          />

          {data.required_ok === false && (
            <p className="error">{t('scanDetail.requiredEngineWarning')}</p>
          )}

          {/* ABOVE the findings, deliberately. The reader's next act is to
              interpret a verdict and a findings list, and "this list was built
              from 9 of 14 engines" changes what both of them mean. Below the
              findings it would be a footnote to a conclusion already drawn.
              Not rendered on a never-scored scan: there is no engine set to
              report on (see `neverScored` below and `_dead_letter_and_decide`). */}
          {!neverScored && <EngineCoverage coverage={data.engine_coverage} />}

          <ScanSignals
            hardGateHits={data.hard_gate_hits}
            trifectaSignals={scanTrifectaSignals(data.findings)}
          />

          {data.reasons.length > 0 && (
            <>
              <h2>{t('scanDetail.reasons')}</h2>
              <ul>
                {/* Machine codes from any of VerdictRow.reasons' producers
                    (gate.py's decide(), orchestration/service.py's sandbox-
                    wait sweep, gate/reviews.py's manual review decision - see
                    i18n/reasons.ts) - rendered through the shared translator
                    rather than printed raw, which is what this page used to
                    do. Keyed by index, not by code: `reasons` is a list, and
                    nothing guarantees two entries can never repeat. */}
                {data.reasons.map((r, i) => (
                  <li key={i}>{reasonLabel(t, r)}</li>
                ))}
              </ul>
            </>
          )}

          <h2>{t('scanDetail.byModule')}</h2>
          {neverScored ? (
            <p className="error">{t('scanDetail.neverScoredNotice')}</p>
          ) : (
            <>
              <p className="hint">{t('scanDetail.byModuleHint')}</p>
              <h2 style={{ fontSize: '0.95rem' }}>{t('scanDetail.byEngine')}</h2>
              <ModuleTable
                rows={byEngine(data, t)}
                moduleLabel={t('scanDetail.colModule')}
                versionLabel={t('scanDetail.colEngineVersion')}
              />
              <h2 style={{ fontSize: '0.95rem' }}>{t('scanDetail.byCategory')}</h2>
              <ModuleTable rows={byCategory(data, t)} moduleLabel={t('scanDetail.colModule')} />
            </>
          )}

          {!neverScored && (
            <>
              <h2>{t('scanDetail.findings', { count: data.findings.length })}</h2>
              {data.findings.length === 0 ? (
                <p className="hint">{t('scanDetail.noFindings')}</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>{t('scanDetail.colRule')}</th>
                        <th>{t('scanDetail.colTitle')}</th>
                        <th>{t('scanDetail.colSeverity')}</th>
                        <th>{t('scanDetail.colConfidence')}</th>
                        <th>{t('scanDetail.colPath')}</th>
                        <th>{t('scanDetail.colEvidence')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.findings.map((f, i) => (
                        <tr key={i}>
                          <td>
                            <code>{f.rule_id}</code>
                          </td>
                          <td>{f.title}</td>
                          <td>
                            <SeverityBadge severity={f.severity} />
                          </td>
                          {/* 0..1, shown as-is rather than as a rounded
                              percentage: it is compared against the policy's
                              own review_confidence (also 0..1), and rounding
                              would hide the difference between 0.69 and 0.70
                              at exactly the threshold that decides REVIEW. */}
                          <td>
                            {typeof f.confidence === 'number' ? f.confidence.toFixed(2) : '—'}
                          </td>
                          <td>
                            {f.file_path ?? '—'}
                            {f.start_line ? `:${f.start_line}` : ''}
                          </td>
                          <td>{f.evidence_redacted || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </>
      )}
    </DataState>
  )
}

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const { t } = useI18n()
  return (
    <div>
      <h1>{t('scanDetail.title', { scanId: scanId ?? '' })}</h1>
      {scanId && <ScanDetailContent scanId={scanId} />}
    </div>
  )
}
