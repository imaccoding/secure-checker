import { buildMonthlyReport } from "./monthly.js";
import { loadYearlyRecord } from "./store.js";

export interface YearlyMonthTotal {
  month: string; // "YYYY-MM"
  scanCount: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface YearlyReport {
  year: string; // "YYYY"
  scanCount: number;
  monthlyTotals: YearlyMonthTotal[];
  /** Change in total finding count from the year's first data point to its last */
  netFindingChange: number;
  /** Rule IDs that appeared as "new" in at least one month and were never marked resolved afterward that year */
  ruleIdsIntroducedThisYear: string[];
  /** Rule IDs that were marked resolved in at least one month during the year */
  ruleIdsResolvedThisYear: string[];
}

/**
 * Builds (or reads back) a yearly trend report by combining each month's report. A closed
 * year that has already been rolled up (see rollup.ts) is read straight from the compact
 * yearly/ record. Otherwise this recombines whatever monthly data is currently available
 * (rolled-up monthly records and/or raw history for months not yet rolled up).
 */
export async function buildYearlyReport(projectRoot: string, year: string): Promise<YearlyReport> {
  const cached = await loadYearlyRecord<YearlyReport>(projectRoot, year);
  if (cached) return cached;
  return computeYearlyReportFromMonths(projectRoot, year);
}

export async function computeYearlyReportFromMonths(projectRoot: string, year: string): Promise<YearlyReport> {
  const months = Array.from({ length: 12 }, (_, i) => `${year}-${String(i + 1).padStart(2, "0")}`);

  const monthlyReports = [];
  for (const month of months) {
    const report = await buildMonthlyReport(projectRoot, month);
    if (report.scanCount > 0) monthlyReports.push(report);
  }

  const monthlyTotals: YearlyMonthTotal[] = monthlyReports.map((r) => ({
    month: r.month,
    scanCount: r.scanCount,
    total: r.latestSummary.total,
    critical: r.latestSummary.critical,
    high: r.latestSummary.high,
    medium: r.latestSummary.medium,
    low: r.latestSummary.low,
    info: r.latestSummary.info,
  }));

  const scanCount = monthlyReports.reduce((sum, r) => sum + r.scanCount, 0);
  const netFindingChange =
    monthlyTotals.length >= 2 ? monthlyTotals[monthlyTotals.length - 1].total - monthlyTotals[0].total : 0;

  const introduced = new Set<string>();
  const resolved = new Set<string>();
  for (const r of monthlyReports) {
    for (const id of r.newRuleIdsSinceStartOfMonth) introduced.add(id);
    for (const id of r.resolvedRuleIdsSinceStartOfMonth) {
      resolved.add(id);
      introduced.delete(id);
    }
  }

  return {
    year,
    scanCount,
    monthlyTotals,
    netFindingChange,
    ruleIdsIntroducedThisYear: [...introduced],
    ruleIdsResolvedThisYear: [...resolved],
  };
}

export function currentYearKey(date: Date = new Date()): string {
  return String(date.getFullYear());
}
