import type { Severity } from "../types.js";
import { loadRawHistoryForMonth, loadMonthlyRecord } from "./store.js";

export interface MonthlyTrendPoint {
  scanAt: string;
  target: string;
  mode: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface MonthlyReport {
  month: string; // "YYYY-MM"
  scanCount: number;
  points: MonthlyTrendPoint[];
  /** Findings present in the most recent scan of the month but not the first - a simple proxy for "newly introduced" */
  newRuleIdsSinceStartOfMonth: string[];
  /** Findings present at the start of the month but gone by the most recent scan - a simple proxy for "resolved" */
  resolvedRuleIdsSinceStartOfMonth: string[];
  latestSummary: Record<Severity, number> & { total: number };
}

/**
 * Builds (or reads back) a monthly trend report. A closed month that has already been
 * rolled up (see rollup.ts) is read straight from the compact monthly/ record instead of
 * re-reading potentially-deleted raw scans. Only the current/not-yet-rolled-up month is
 * computed from raw history on demand.
 */
export async function buildMonthlyReport(projectRoot: string, month: string): Promise<MonthlyReport> {
  const cached = await loadMonthlyRecord<MonthlyReport>(projectRoot, month);
  if (cached) return cached;
  return computeMonthlyReportFromRaw(projectRoot, month);
}

export async function computeMonthlyReportFromRaw(projectRoot: string, month: string): Promise<MonthlyReport> {
  const inMonth = await loadRawHistoryForMonth(projectRoot, month);

  const points: MonthlyTrendPoint[] = inMonth.map((r) => ({
    scanAt: r.finishedAt,
    target: r.target,
    mode: r.mode,
    total: r.summary.total,
    critical: r.summary.critical,
    high: r.summary.high,
    medium: r.summary.medium,
    low: r.summary.low,
    info: r.summary.info,
  }));

  let newRuleIds: string[] = [];
  let resolvedRuleIds: string[] = [];
  let latestSummary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  if (inMonth.length > 0) {
    const first = inMonth[0];
    const latest = inMonth[inMonth.length - 1];
    const firstRuleIds = new Set(first.findings.map((f) => f.ruleId));
    const latestRuleIds = new Set(latest.findings.map((f) => f.ruleId));

    newRuleIds = [...latestRuleIds].filter((id) => !firstRuleIds.has(id));
    resolvedRuleIds = [...firstRuleIds].filter((id) => !latestRuleIds.has(id));
    latestSummary = latest.summary;
  }

  return {
    month,
    scanCount: inMonth.length,
    points,
    newRuleIdsSinceStartOfMonth: newRuleIds,
    resolvedRuleIdsSinceStartOfMonth: resolvedRuleIds,
    latestSummary,
  };
}

export function currentMonthKey(date: Date = new Date()): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
}
