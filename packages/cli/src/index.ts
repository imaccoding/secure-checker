#!/usr/bin/env node
import { Command } from "commander";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  scanCodebase,
  scanWebsite,
  renderReport,
  saveScanToHistory,
  buildMonthlyReport,
  currentMonthKey,
  buildYearlyReport,
  currentYearKey,
  rollupHistory,
  type ReportFormat,
  type ScanMode,
  type ScanResult,
} from "@secure-checker/core";

const program = new Command();

program
  .name("secure-checker")
  .description("Security checker for source code and live websites")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a local codebase for secrets, dangerous code patterns, vulnerable dependencies, and risky config")
  .argument("<path>", "Path to the codebase (file or directory)")
  .option("-m, --mode <mode>", "quick | detailed", "quick")
  .option("-f, --format <format>", "html | markdown | json", "html")
  .option("-o, --out <file>", "Write the report to a file instead of stdout")
  .option("--no-history", "Do not save this scan to local history")
  .action(async (path, opts) => {
    const mode = validateMode(opts.mode);
    const target = resolve(path);
    const result = await scanCodebase(target, {
      mode,
      onProgress: (msg) => process.stderr.write(`[secure-checker] ${msg}\n`),
    });
    await emitReport(result, opts.format, opts.out);
    if (opts.history) {
      await saveHistoryAndRollup(target, result);
    }
    exitWithSeverity(result);
  });

program
  .command("scan-web")
  .description("Scan a live website for missing security headers, cookie flags, TLS issues, and common exposures")
  .argument("<url>", "URL to scan, e.g. https://example.com")
  .option("-m, --mode <mode>", "quick | detailed", "quick")
  .option("-f, --format <format>", "html | markdown | json", "html")
  .option("-o, --out <file>", "Write the report to a file instead of stdout")
  .option("--no-history", "Do not save this scan to local history")
  .action(async (url, opts) => {
    const mode = validateMode(opts.mode);
    const result = await scanWebsite(url, {
      mode,
      onProgress: (msg) => process.stderr.write(`[secure-checker] ${msg}\n`),
    });
    await emitReport(result, opts.format, opts.out);
    if (opts.history) {
      await saveHistoryAndRollup(process.cwd(), result);
    }
    exitWithSeverity(result);
  });

const history = program.command("history").description("Work with locally stored scan history");

history
  .command("monthly")
  .description("Build a monthly trend report from local scan history (requires prior scans run with history enabled)")
  .option("-p, --project <path>", "Project root whose .secure-checker/history to read", ".")
  .option("--month <YYYY-MM>", "Month to report on", currentMonthKey())
  .option("-o, --out <file>", "Write JSON report to a file instead of stdout")
  .action(async (opts) => {
    const report = await buildMonthlyReport(resolve(opts.project), opts.month);
    await writeJsonOutput(report, opts.out, "monthly report");
  });

history
  .command("yearly")
  .description("Build a yearly trend report (per-month totals across the year) from local scan history")
  .option("-p, --project <path>", "Project root whose .secure-checker/history to read", ".")
  .option("--year <YYYY>", "Year to report on", currentYearKey())
  .option("-o, --out <file>", "Write JSON report to a file instead of stdout")
  .action(async (opts) => {
    const report = await buildYearlyReport(resolve(opts.project), opts.year);
    await writeJsonOutput(report, opts.out, "yearly report");
  });

history
  .command("rollup")
  .description(
    "Compact old raw scans into monthly summaries, and old monthly summaries into yearly summaries, to keep history storage bounded over time"
  )
  .option("-p, --project <path>", "Project root whose .secure-checker/history to compact", ".")
  .option("--raw-retention-days <n>", "Days of full-detail raw scans to keep before compacting into a monthly summary", "90")
  .option("--monthly-retention-months <n>", "Months of monthly summaries to keep before compacting into a yearly summary", "24")
  .action(async (opts) => {
    const result = await rollupHistory(resolve(opts.project), {
      rawRetentionDays: Number(opts.rawRetentionDays),
      monthlyRetentionMonths: Number(opts.monthlyRetentionMonths),
    });
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});

function validateMode(mode: string): ScanMode {
  if (mode !== "quick" && mode !== "detailed") {
    throw new Error(`Invalid --mode "${mode}". Expected "quick" or "detailed".`);
  }
  return mode;
}

async function emitReport(result: ScanResult, format: string, outFile?: string): Promise<void> {
  const fmt = validateFormat(format);
  const content = renderReport(result, fmt);
  if (outFile) {
    await writeFile(outFile, content, "utf8");
    process.stderr.write(`[secure-checker] report written to ${outFile}\n`);
  } else {
    process.stdout.write(content + "\n");
  }
  process.stderr.write(
    `[secure-checker] ${result.summary.total} finding(s): ` +
      `${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low, ${result.summary.info} info\n`
  );
}

function validateFormat(format: string): ReportFormat {
  if (format !== "html" && format !== "markdown" && format !== "json") {
    throw new Error(`Invalid --format "${format}". Expected "html", "markdown", or "json".`);
  }
  return format;
}

function exitWithSeverity(result: ScanResult): void {
  // Non-zero exit when critical/high findings exist, useful for CI gating.
  if (result.summary.critical > 0 || result.summary.high > 0) {
    process.exitCode = 1;
  }
}

async function saveHistoryAndRollup(projectRoot: string, result: ScanResult): Promise<void> {
  const saved = await saveScanToHistory(projectRoot, result);
  process.stderr.write(`[secure-checker] history saved: ${saved}\n`);
  // Cheap no-op unless a month/year has actually aged past its retention window.
  const rollup = await rollupHistory(projectRoot);
  if (rollup.monthsCompacted.length > 0 || rollup.yearsCompacted.length > 0) {
    process.stderr.write(
      `[secure-checker] history rollup: compacted month(s) [${rollup.monthsCompacted.join(", ")}], year(s) [${rollup.yearsCompacted.join(", ")}]\n`
    );
  }
}

async function writeJsonOutput(data: unknown, outFile: string | undefined, label: string): Promise<void> {
  const json = JSON.stringify(data, null, 2);
  if (outFile) {
    await writeFile(outFile, json, "utf8");
    process.stderr.write(`[secure-checker] ${label} written to ${outFile}\n`);
  } else {
    process.stdout.write(json + "\n");
  }
}
