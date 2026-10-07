import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { saveScanToHistory, rawDir, monthlyDir, yearlyDir } from "../history/store.js";
import { buildMonthlyReport } from "../history/monthly.js";
import { buildYearlyReport } from "../history/yearly.js";
import { rollupHistory } from "../history/rollup.js";
import { summarize, sortFindings, type Finding, type ScanResult } from "../types.js";

function makeScan(finishedAt: string, findings: Finding[]): ScanResult {
  const sorted = sortFindings(findings);
  return {
    target: "test-project",
    targetType: "codebase",
    mode: "quick",
    startedAt: finishedAt,
    finishedAt,
    durationMs: 10,
    findings: sorted,
    summary: summarize(sorted),
  };
}

async function withTempProject(fn: (root: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "secure-checker-test-"));
  try {
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("saveScanToHistory writes into the raw/ tier, grouped by month", () =>
  withTempProject(async (root) => {
    await saveScanToHistory(root, makeScan("2026-03-15T10:00:00.000Z", []));
    const files = await readdir(rawDir(root));
    assert.equal(files.length, 1);
    assert.ok(files[0].startsWith("2026-03_"));
  }));

test("buildMonthlyReport computes new/resolved rule IDs across a month's scans", () =>
  withTempProject(async (root) => {
    const critical: Finding = { ruleId: "secret-aws-access-key", title: "x", severity: "critical", category: "secret", description: "d", remediation: "r" };
    const low: Finding = { ruleId: "code-generic-http-url", title: "y", severity: "low", category: "code", description: "d", remediation: "r" };

    await saveScanToHistory(root, makeScan("2026-03-01T00:00:00.000Z", [critical]));
    await saveScanToHistory(root, makeScan("2026-03-20T00:00:00.000Z", [low]));

    const report = await buildMonthlyReport(root, "2026-03");
    assert.equal(report.scanCount, 2);
    assert.deepEqual(report.newRuleIdsSinceStartOfMonth, ["code-generic-http-url"]);
    assert.deepEqual(report.resolvedRuleIdsSinceStartOfMonth, ["secret-aws-access-key"]);
    assert.equal(report.latestSummary.total, 1);
  }));

test("rollupHistory never compacts the current (in-progress) month", () =>
  withTempProject(async (root) => {
    const now = new Date();
    await saveScanToHistory(root, makeScan(now.toISOString(), []));
    const result = await rollupHistory(root, { rawRetentionDays: 0, monthlyRetentionMonths: 0, now });
    assert.deepEqual(result.monthsCompacted, []);
    const rawFiles = await readdir(rawDir(root));
    assert.equal(rawFiles.length, 1, "raw file for the current month must survive rollup");
  }));

test("rollupHistory compacts an old month into monthly/, then an old year into yearly/", () =>
  withTempProject(async (root) => {
    const now = new Date("2026-10-07T00:00:00.000Z");
    const oldFinding: Finding = { ruleId: "secret-aws-access-key", title: "x", severity: "critical", category: "secret", description: "d", remediation: "r" };
    await saveScanToHistory(root, makeScan("2024-01-15T00:00:00.000Z", [oldFinding]));

    const result = await rollupHistory(root, { rawRetentionDays: 90, monthlyRetentionMonths: 24, now });

    assert.deepEqual(result.monthsCompacted, ["2024-01"]);
    assert.deepEqual(result.yearsCompacted, ["2024"]);
    assert.equal(result.rawFilesRemoved, 1);

    const rawFiles = await readdir(rawDir(root)).catch(() => []);
    assert.equal(rawFiles.length, 0, "raw file should have been deleted after compaction");

    const monthlyFiles = await readdir(monthlyDir(root)).catch(() => []);
    assert.equal(monthlyFiles.length, 0, "monthly file should have been compacted straight into yearly in the same pass");

    const yearly = await buildYearlyReport(root, "2024");
    assert.equal(yearly.scanCount, 1);
    assert.equal(yearly.monthlyTotals[0].critical, 1);

    const yearlyFiles = await readdir(yearlyDir(root));
    assert.equal(yearlyFiles.length, 1);
  }));
