import * as vscode from "vscode";
import * as path from "node:path";
import * as core from "@secure-checker/core";
import type { Finding, ScanResult, MonthlyReport, YearlyReport } from "@secure-checker/core";

// @secure-checker/core is ESM; esbuild bundles it straight into this CJS extension.js at
// build time (see esbuild.config.mjs), so this is a plain static import.

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection("secureChecker");
  outputChannel = vscode.window.createOutputChannel("Secure Checker");
  context.subscriptions.push(diagnosticCollection, outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("secureChecker.quickScanWorkspace", () => scanWorkspace("quick")),
    vscode.commands.registerCommand("secureChecker.detailedScanWorkspace", () => scanWorkspace("detailed")),
    vscode.commands.registerCommand("secureChecker.scanCurrentFile", () => scanCurrentFile()),
    vscode.commands.registerCommand("secureChecker.scanWebsite", () => scanWebsiteCommand()),
    vscode.commands.registerCommand("secureChecker.showMonthlyReport", () => showMonthlyReport()),
    vscode.commands.registerCommand("secureChecker.showYearlyReport", () => showYearlyReport())
  );

  // Best-effort: compact any history left over from previous sessions. No-op unless
  // something has actually aged past its retention window (see core.rollupHistory).
  const root = getWorkspaceRoot();
  if (root && saveHistoryEnabled()) {
    core.rollupHistory(root, retentionOptions()).catch(() => {});
  }
}

export function deactivate() {}

function getWorkspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function saveHistoryEnabled(): boolean {
  return vscode.workspace.getConfiguration("secureChecker").get<boolean>("saveHistory", true);
}

function retentionOptions() {
  const config = vscode.workspace.getConfiguration("secureChecker");
  return {
    rawRetentionDays: config.get<number>("rawRetentionDays", 90),
    monthlyRetentionMonths: config.get<number>("monthlyRetentionMonths", 24),
  };
}

async function saveHistoryAndRollup(root: string, result: ScanResult) {
  await core.saveScanToHistory(root, result);
  await core.rollupHistory(root, retentionOptions());
}

async function scanWorkspace(mode: "quick" | "detailed") {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Secure Checker: open a folder/workspace first.");
    return;
  }

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Secure Checker: ${mode} scan`, cancellable: false },
    async (progress) => {
      outputChannel.clear();
      const result = await core.scanCodebase(root, {
        mode,
        onProgress: (msg) => {
          progress.report({ message: msg });
          outputChannel.appendLine(msg);
        },
      });

      applyDiagnostics(root, result.findings);
      if (saveHistoryEnabled()) {
        await saveHistoryAndRollup(root, result);
      }
      await showReportWebview(result);
    }
  );
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Secure Checker: no active file.");
    return;
  }
  const filePath = editor.document.uri.fsPath;

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "Secure Checker: scanning file", cancellable: false },
    async () => {
      const result = await core.scanCodebase(filePath, { mode: "detailed" });
      const root = getWorkspaceRoot() ?? filePath;
      applyDiagnostics(root, result.findings);
      await showReportWebview(result);
    }
  );
}

async function scanWebsiteCommand() {
  const url = await vscode.window.showInputBox({
    prompt: "URL to scan (e.g. https://example.com)",
    validateInput: (v) => (v.trim().length === 0 ? "Enter a URL" : undefined),
  });
  if (!url) return;

  const mode = await vscode.window.showQuickPick(["quick", "detailed"], { placeHolder: "Scan mode" });
  if (!mode) return;

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `Secure Checker: scanning ${url}`, cancellable: false },
    async (progress) => {
      const result = await core.scanWebsite(url, {
        mode: mode as "quick" | "detailed",
        onProgress: (msg) => progress.report({ message: msg }),
      });
      const root = getWorkspaceRoot();
      if (root && saveHistoryEnabled()) {
        await saveHistoryAndRollup(root, result);
      }
      await showReportWebview(result);
    }
  );
}

async function showMonthlyReport() {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Secure Checker: open a folder/workspace first.");
    return;
  }
  const report = await core.buildMonthlyReport(root, core.currentMonthKey());

  const panel = vscode.window.createWebviewPanel(
    "secureCheckerMonthly",
    `Secure Checker - Monthly Trend (${report.month})`,
    vscode.ViewColumn.Active,
    {}
  );
  panel.webview.html = monthlyReportHtml(report);
}

async function showYearlyReport() {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Secure Checker: open a folder/workspace first.");
    return;
  }
  const report = await core.buildYearlyReport(root, core.currentYearKey());

  const panel = vscode.window.createWebviewPanel(
    "secureCheckerYearly",
    `Secure Checker - Yearly Trend (${report.year})`,
    vscode.ViewColumn.Active,
    {}
  );
  panel.webview.html = yearlyReportHtml(report);
}

function applyDiagnostics(root: string, findings: Finding[]) {
  diagnosticCollection.clear();
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.file) continue;
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  for (const [relFile, list] of byFile) {
    const absPath = path.isAbsolute(relFile) ? relFile : path.join(root, relFile);
    const uri = vscode.Uri.file(absPath);
    const diagnostics = list.map((f) => {
      const line = Math.max((f.line ?? 1) - 1, 0);
      const range = new vscode.Range(line, 0, line, 200);
      const diagnostic = new vscode.Diagnostic(
        range,
        `[${f.ruleId}] ${f.title}: ${f.description}\nFix: ${f.remediation}`,
        severityToVscode(f.severity)
      );
      diagnostic.source = "Secure Checker";
      return diagnostic;
    });
    diagnosticCollection.set(uri, diagnostics);
  }
}

function severityToVscode(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

async function showReportWebview(result: ScanResult) {
  const html = core.renderReport(result, "html");
  const panel = vscode.window.createWebviewPanel(
    "secureCheckerReport",
    `Secure Checker: ${result.target}`,
    vscode.ViewColumn.Active,
    { enableScripts: false }
  );
  panel.webview.html = html;

  const msg = `${result.summary.total} finding(s) - ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low, ${result.summary.info} info`;
  if (result.summary.critical > 0) {
    vscode.window.showErrorMessage(`Secure Checker: ${msg}`);
  } else if (result.summary.high > 0) {
    vscode.window.showWarningMessage(`Secure Checker: ${msg}`);
  } else {
    vscode.window.showInformationMessage(`Secure Checker: ${msg}`);
  }
}

function monthlyReportHtml(report: MonthlyReport): string {
  const rows = report.points
    .map(
      (p) =>
        `<tr><td>${esc(p.scanAt)}</td><td>${esc(p.mode)}</td><td>${p.total}</td><td>${p.critical}</td><td>${p.high}</td><td>${p.medium}</td><td>${p.low}</td><td>${p.info}</td></tr>`
    )
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    body{font-family:sans-serif;padding:1.5rem;}
    table{border-collapse:collapse;width:100%;}
    td,th{border:1px solid #444;padding:0.4rem 0.6rem;text-align:left;}
  </style></head><body>
  <h1>Monthly Trend - ${esc(report.month)}</h1>
  <p>${report.scanCount} scan(s) recorded this month.</p>
  <table><thead><tr><th>Scanned At</th><th>Mode</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="8">No scans recorded this month yet.</td></tr>'}</tbody></table>
  <h3>New since start of month</h3><p>${report.newRuleIdsSinceStartOfMonth.map(esc).join(", ") || "None"}</p>
  <h3>Resolved since start of month</h3><p>${report.resolvedRuleIdsSinceStartOfMonth.map(esc).join(", ") || "None"}</p>
  </body></html>`;
}

function yearlyReportHtml(report: YearlyReport): string {
  const rows = report.monthlyTotals
    .map(
      (m) =>
        `<tr><td>${esc(m.month)}</td><td>${m.scanCount}</td><td>${m.total}</td><td>${m.critical}</td><td>${m.high}</td><td>${m.medium}</td><td>${m.low}</td><td>${m.info}</td></tr>`
    )
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    body{font-family:sans-serif;padding:1.5rem;}
    table{border-collapse:collapse;width:100%;}
    td,th{border:1px solid #444;padding:0.4rem 0.6rem;text-align:left;}
  </style></head><body>
  <h1>Yearly Trend - ${esc(report.year)}</h1>
  <p>${report.scanCount} scan(s) recorded this year. Net finding change over the year: ${report.netFindingChange >= 0 ? "+" : ""}${report.netFindingChange}.</p>
  <table><thead><tr><th>Month</th><th>Scans</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="8">No scans recorded this year yet.</td></tr>'}</tbody></table>
  <h3>Introduced this year (still open)</h3><p>${report.ruleIdsIntroducedThisYear.map(esc).join(", ") || "None"}</p>
  <h3>Resolved this year</h3><p>${report.ruleIdsResolvedThisYear.map(esc).join(", ") || "None"}</p>
  </body></html>`;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
