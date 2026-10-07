import { mkdir, readdir, readFile, writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { ScanResult } from "../types.js";

/**
 * Local history of scan results, stored under <projectRoot>/.secure-checker/history/
 * in three tiers so storage stays bounded over years of use:
 *
 *   raw/      one full ScanResult JSON per scan (all findings, recent scans only)
 *   monthly/  one compact MonthlyReport JSON per closed month, after raw detail for
 *             that month has aged past the retention window (see rollup.ts)
 *   yearly/   one compact YearlyReport JSON per closed year, after that year's
 *             monthly files have aged past their own retention window
 *
 * Raw filenames are prefixed with their "YYYY-MM" so a month's files can be grouped
 * without reading every file's contents.
 */
export function historyDir(projectRoot: string): string {
  return join(projectRoot, ".secure-checker", "history");
}

export function rawDir(projectRoot: string): string {
  return join(historyDir(projectRoot), "raw");
}

export function monthlyDir(projectRoot: string): string {
  return join(historyDir(projectRoot), "monthly");
}

export function yearlyDir(projectRoot: string): string {
  return join(historyDir(projectRoot), "yearly");
}

function monthKeyOf(isoTimestamp: string): string {
  return isoTimestamp.slice(0, 7); // "YYYY-MM"
}

function yearKeyOf(monthKey: string): string {
  return monthKey.slice(0, 4); // "YYYY"
}

export async function saveScanToHistory(projectRoot: string, result: ScanResult): Promise<string> {
  const dir = rawDir(projectRoot);
  await mkdir(dir, { recursive: true });

  const targetHash = createHash("sha1").update(result.target).digest("hex").slice(0, 8);
  const safeTimestamp = result.finishedAt.replace(/[:.]/g, "-");
  const month = monthKeyOf(result.finishedAt);
  const fileName = `${month}_${safeTimestamp}_${result.mode}_${targetHash}.json`;
  const filePath = join(dir, fileName);

  await writeFile(filePath, JSON.stringify(result, null, 2), "utf8");
  return filePath;
}

async function listJsonFiles(dir: string): Promise<string[]> {
  try {
    return (await readdir(dir)).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
}

/** All raw (full-detail) scan results currently retained, oldest first. */
export async function loadRawHistory(projectRoot: string): Promise<ScanResult[]> {
  const dir = rawDir(projectRoot);
  const files = await listJsonFiles(dir);

  const results: ScanResult[] = [];
  for (const file of files) {
    try {
      const content = await readFile(join(dir, file), "utf8");
      results.push(JSON.parse(content));
    } catch {
      // skip unreadable/corrupt history entries
    }
  }

  results.sort((a, b) => new Date(a.finishedAt).getTime() - new Date(b.finishedAt).getTime());
  return results;
}

/** Raw scan results for one specific "YYYY-MM" month, oldest first. */
export async function loadRawHistoryForMonth(projectRoot: string, month: string): Promise<ScanResult[]> {
  const dir = rawDir(projectRoot);
  const files = (await listJsonFiles(dir)).filter((f) => f.startsWith(`${month}_`));

  const results: ScanResult[] = [];
  for (const file of files) {
    try {
      const content = await readFile(join(dir, file), "utf8");
      results.push(JSON.parse(content));
    } catch {
      // skip unreadable/corrupt history entries
    }
  }
  results.sort((a, b) => new Date(a.finishedAt).getTime() - new Date(b.finishedAt).getTime());
  return results;
}

/** Distinct "YYYY-MM" months present in the raw tier, derived from filenames (no file reads). */
export async function listRawMonths(projectRoot: string): Promise<string[]> {
  const files = await listJsonFiles(rawDir(projectRoot));
  const months = new Set<string>();
  for (const f of files) {
    const match = /^(\d{4}-\d{2})_/.exec(f);
    if (match) months.add(match[1]);
  }
  return [...months].sort();
}

export async function deleteRawFilesForMonth(projectRoot: string, month: string): Promise<number> {
  const dir = rawDir(projectRoot);
  const files = (await listJsonFiles(dir)).filter((f) => f.startsWith(`${month}_`));
  for (const f of files) {
    await unlink(join(dir, f)).catch(() => {});
  }
  return files.length;
}

export async function saveMonthlyRecord(projectRoot: string, month: string, record: unknown): Promise<string> {
  const dir = monthlyDir(projectRoot);
  await mkdir(dir, { recursive: true });
  const filePath = join(dir, `${month}.json`);
  await writeFile(filePath, JSON.stringify(record, null, 2), "utf8");
  return filePath;
}

export async function loadMonthlyRecord<T = unknown>(projectRoot: string, month: string): Promise<T | undefined> {
  try {
    const content = await readFile(join(monthlyDir(projectRoot), `${month}.json`), "utf8");
    return JSON.parse(content) as T;
  } catch {
    return undefined;
  }
}

/** Distinct "YYYY-MM" months present in the monthly (rolled-up) tier. */
export async function listMonthlyRecords(projectRoot: string): Promise<string[]> {
  const files = await listJsonFiles(monthlyDir(projectRoot));
  return files.map((f) => f.replace(/\.json$/, "")).sort();
}

export async function deleteMonthlyRecordsForYear(projectRoot: string, year: string): Promise<number> {
  const dir = monthlyDir(projectRoot);
  const files = (await listJsonFiles(dir)).filter((f) => f.startsWith(`${year}-`));
  for (const f of files) {
    await unlink(join(dir, f)).catch(() => {});
  }
  return files.length;
}

export async function saveYearlyRecord(projectRoot: string, year: string, record: unknown): Promise<string> {
  const dir = yearlyDir(projectRoot);
  await mkdir(dir, { recursive: true });
  const filePath = join(dir, `${year}.json`);
  await writeFile(filePath, JSON.stringify(record, null, 2), "utf8");
  return filePath;
}

export async function loadYearlyRecord<T = unknown>(projectRoot: string, year: string): Promise<T | undefined> {
  try {
    const content = await readFile(join(yearlyDir(projectRoot), `${year}.json`), "utf8");
    return JSON.parse(content) as T;
  } catch {
    return undefined;
  }
}

export { yearKeyOf, monthKeyOf };

/** @deprecated use loadRawHistory - kept as an alias so existing callers keep working */
export const loadHistory = loadRawHistory;
