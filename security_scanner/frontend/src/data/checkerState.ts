// ---------------------------------------------------------------------------
// Checker-state normalisation — the correctness backbone of the redesign.
//
// Rules enforced (spec §7, §22, §28, §33):
//   * A checker that did not complete (blocked / error / no_data / no API key /
//     subscription_required / rate_limited / skipped) NEVER renders green and
//     NEVER renders as a "pass".
//   * "passed" is only ever derived by a checker that actually completed with
//     genuinely passing semantics — decided per-metric in selectors, not from
//     score===100 or an empty issues list alone.
// ---------------------------------------------------------------------------
import type { CategoryBase, CheckerState, Severity } from '../types/results'

export interface StateMeta {
  /** human label for the state */
  label: string
  /** severity drives colour + icon */
  severity: Severity
  /** true when the checker produced a real verdict (pass/fail/etc.) */
  conclusive: boolean
}

export const STATE_META: Record<CheckerState, StateMeta> = {
  passed: { label: 'Passed', severity: 'positive', conclusive: true },
  warning: { label: 'Warning', severity: 'medium', conclusive: true },
  failed: { label: 'Failed', severity: 'high', conclusive: true },
  critical: { label: 'Critical', severity: 'critical', conclusive: true },
  blocked: { label: 'Blocked', severity: 'medium', conclusive: false },
  error: { label: 'Checker error', severity: 'unknown', conclusive: false },
  not_assessed: { label: 'Not assessed', severity: 'unknown', conclusive: false },
  no_data: { label: 'No data', severity: 'unknown', conclusive: false },
  not_applicable: { label: 'Not applicable', severity: 'unknown', conclusive: false },
  subscription_required: { label: 'Subscription required', severity: 'unknown', conclusive: false },
  rate_limited: { label: 'Rate limited', severity: 'unknown', conclusive: false },
  skipped: { label: 'Skipped', severity: 'unknown', conclusive: false },
}

// Raw scanner `status` strings → canonical CheckerState. Anything that means
// "the checker ran and produced findings" maps to 'passed' as a NEUTRAL run
// marker; callers then refine to warning/failed/critical from the actual
// findings. Anything inconclusive keeps its own non-green state.
const RAW_STATE_MAP: Record<string, CheckerState> = {
  completed: 'passed',
  complete: 'passed',
  ok: 'passed',
  success: 'passed',
  done: 'passed',
  passed: 'passed',
  pass: 'passed',

  warning: 'warning',
  warn: 'warning',

  failed: 'failed',
  fail: 'failed',
  failure: 'failed',

  critical: 'critical',

  blocked: 'blocked',
  waf_blocked: 'blocked',
  forbidden: 'blocked',

  error: 'error',
  exception: 'error',
  timeout: 'error',
  timed_out: 'error',

  no_api_key: 'not_assessed',
  no_key: 'not_assessed',
  missing_api_key: 'not_assessed',
  unreachable: 'not_assessed',
  not_assessed: 'not_assessed',
  unknown: 'not_assessed',

  no_data: 'no_data',
  empty: 'no_data',
  none: 'no_data',

  not_applicable: 'not_applicable',
  na: 'not_applicable',
  'n/a': 'not_applicable',

  subscription_required: 'subscription_required',
  requires_subscription: 'subscription_required',
  paid: 'subscription_required',

  rate_limited: 'rate_limited',
  ratelimited: 'rate_limited',
  throttled: 'rate_limited',

  skipped: 'skipped',
  skip: 'skipped',
  disabled: 'skipped',
}

export function normalizeState(raw: string | null | undefined): CheckerState {
  if (!raw) return 'not_assessed'
  return RAW_STATE_MAP[String(raw).toLowerCase().trim()] ?? 'not_assessed'
}

/** Did a checker actually run to a verdict? false for blocked/error/no-data/etc. */
export function isConclusive(category: CategoryBase | undefined): boolean {
  return STATE_META[normalizeState(category?.status)].conclusive
}

/** Friendlier label for inconclusive states, with the no-API-key nuance. */
export function inconclusiveLabel(raw: string | null | undefined): string {
  const r = String(raw ?? '').toLowerCase().trim()
  if (r === 'no_api_key' || r === 'no_key' || r === 'missing_api_key') return 'No API key'
  if (r === 'unreachable') return 'Unreachable'
  return STATE_META[normalizeState(raw)].label
}

// --- severity → presentation (colour var + short code) ----------------------

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--warning)',
  low: 'var(--info)',
  info: 'var(--info)',
  positive: 'var(--positive)',
  unknown: 'var(--unknown)',
}

export const SEVERITY_SOFT: Record<Severity, string> = {
  critical: 'var(--critical-soft)',
  high: 'var(--high-soft)',
  medium: 'var(--warning-soft)',
  low: 'var(--info-soft)',
  info: 'var(--info-soft)',
  positive: 'var(--positive-soft)',
  unknown: 'var(--unknown-soft)',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  positive: 'Positive',
  unknown: 'Unknown',
}

/** Normalise an arbitrary severity-ish string from the payload. */
export function normalizeSeverity(raw: string | null | undefined): Severity {
  const r = String(raw ?? '').toLowerCase().trim()
  if (r === 'critical' || r === 'crit') return 'critical'
  if (r === 'high') return 'high'
  if (r === 'medium' || r === 'med' || r === 'moderate' || r === 'warning') return 'medium'
  if (r === 'low') return 'low'
  if (r === 'info' || r === 'informational') return 'info'
  if (r === 'positive' || r === 'good' || r === 'pass') return 'positive'
  return 'unknown'
}

export function severityRank(sev: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1, positive: 0, unknown: 1 }[sev]
}
