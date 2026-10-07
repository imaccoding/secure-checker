# Secure Checker

Scan your workspace or a live website for security risks - quick or detailed - with a remediation
report for every finding.

## Commands

- **Secure Checker: Quick Scan Workspace** - fast pass over the open folder (secrets + dangerous
  code patterns + config checks).
- **Secure Checker: Detailed Scan Workspace** - adds dependency audit (`npm audit`/`pip-audit`).
- **Secure Checker: Scan Current File**
- **Secure Checker: Scan a Website URL** - checks security headers, cookie flags, HTTPS, and (in
  detailed mode) TLS certificate status and common exposed paths.
- **Secure Checker: Show Monthly Trend Report** / **Show Yearly Trend Report** - trend of findings
  over time, built from locally stored scan history.

Findings appear both in the Problems panel and in a full HTML report.

## Settings

- `secureChecker.saveHistory` - save each scan to `.secure-checker/history` in the workspace
  (default: on).
- `secureChecker.rawRetentionDays` - how long full-detail scan history is kept before being
  compacted into a monthly summary (default: 90).
- `secureChecker.monthlyRetentionMonths` - how long monthly summaries are kept before being
  compacted into a yearly summary (default: 24).
