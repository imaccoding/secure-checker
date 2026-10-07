import {
  listRawMonths,
  deleteRawFilesForMonth,
  saveMonthlyRecord,
  listMonthlyRecords,
  deleteMonthlyRecordsForYear,
  saveYearlyRecord,
  loadMonthlyRecord,
} from "./store.js";
import { computeMonthlyReportFromRaw, currentMonthKey, type MonthlyReport } from "./monthly.js";
import { computeYearlyReportFromMonths, currentYearKey } from "./yearly.js";

export interface RollupOptions {
  /** Full-detail raw scans older than this many days (by month boundary) get compacted into a monthly summary. Default 90. */
  rawRetentionDays?: number;
  /** Monthly summaries for years closed more than this many months ago get compacted into a yearly summary. Default 24. */
  monthlyRetentionMonths?: number;
  now?: Date;
}

export interface RollupResult {
  monthsCompacted: string[];
  yearsCompacted: string[];
  rawFilesRemoved: number;
  monthlyFilesRemoved: number;
}

/**
 * Keeps local scan history storage bounded over years of use:
 *  - closed months whose raw scans are older than `rawRetentionDays` get compacted into a
 *    single monthly/<YYYY-MM>.json summary, and their raw files are deleted.
 *  - closed years whose monthly summaries are older than `monthlyRetentionMonths` get
 *    compacted into a single yearly/<YYYY>.json summary, and the monthly files are deleted.
 *
 * Safe to call on every scan (it's a cheap no-op when nothing is old enough yet) - the CLI
 * and VS Code extension both call this after saving a new scan to history.
 */
export async function rollupHistory(projectRoot: string, options: RollupOptions = {}): Promise<RollupResult> {
  const now = options.now ?? new Date();
  const rawRetentionDays = options.rawRetentionDays ?? 90;
  const monthlyRetentionMonths = options.monthlyRetentionMonths ?? 24;

  const result: RollupResult = { monthsCompacted: [], yearsCompacted: [], rawFilesRemoved: 0, monthlyFilesRemoved: 0 };

  // --- raw -> monthly ---
  const thisMonth = currentMonthKey(now);
  const rawCutoff = new Date(now.getTime() - rawRetentionDays * 24 * 60 * 60 * 1000);
  const rawCutoffMonth = currentMonthKey(rawCutoff);

  const rawMonths = await listRawMonths(projectRoot);
  for (const month of rawMonths) {
    if (month >= thisMonth) continue; // never compact the in-progress month
    if (month > rawCutoffMonth) continue; // not old enough yet
    const existing = await loadMonthlyRecord<MonthlyReport>(projectRoot, month);
    if (!existing) {
      const report = await computeMonthlyReportFromRaw(projectRoot, month);
      await saveMonthlyRecord(projectRoot, month, report);
    }
    const removed = await deleteRawFilesForMonth(projectRoot, month);
    result.rawFilesRemoved += removed;
    result.monthsCompacted.push(month);
  }

  // --- monthly -> yearly ---
  const thisYear = currentYearKey(now);
  const monthlyCutoff = new Date(now.getTime());
  monthlyCutoff.setMonth(monthlyCutoff.getMonth() - monthlyRetentionMonths);
  const monthlyCutoffYear = currentYearKey(monthlyCutoff);

  const monthlyMonths = await listMonthlyRecords(projectRoot);
  const monthlyYears = new Set(monthlyMonths.map((m) => m.slice(0, 4)));
  for (const year of monthlyYears) {
    if (year >= thisYear) continue; // never compact the in-progress year
    if (year > monthlyCutoffYear) continue; // not old enough yet
    const yearlyReport = await computeYearlyReportFromMonths(projectRoot, year);
    await saveYearlyRecord(projectRoot, year, yearlyReport);
    const removed = await deleteMonthlyRecordsForYear(projectRoot, year);
    result.monthlyFilesRemoved += removed;
    result.yearsCompacted.push(year);
  }

  return result;
}
