# Secure Checker

A security checker for source code and live websites: finds hardcoded secrets, dangerous code
patterns, vulnerable dependencies, risky config, and missing web security controls, then produces
a report with concrete remediation for each finding. Supports **Quick** (fast, no network calls
beyond the target itself) and **Detailed** (adds dependency audit, TLS certificate check, and
common exposed-path probing) modes.

## Structure

This is an npm workspaces monorepo:

- `packages/core` - the scanning engine (rules, report generation, history/trend tracking). Pure
  TypeScript, used by every surface below.
- `packages/cli` - `secure-checker` command-line tool.
- `packages/vscode-extension` - VS Code extension (Problems-panel diagnostics + HTML report webview).
- `packages/web-extension` - Chrome/Edge (Manifest V3) browser extension that checks the site you're
  currently on (headers, cookies, HTTPS, and in detailed mode, common exposed paths).

## What it checks

- **Secrets** - AWS/GitHub/Slack/Stripe/Google keys, private key blocks, JWTs, DB connection
  strings with embedded credentials, generic `password=`/`api_key=` assignments.
- **Dangerous code patterns (SAST)** - JS/TS (`eval`, command injection, disabled TLS verification,
  `innerHTML`/`dangerouslySetInnerHTML`, weak randomness for tokens, wildcard CORS, SQL string
  concatenation), Python (`pickle.loads`, unsafe YAML load, `shell=True`, Flask/Django debug mode),
  PHP (`unserialize`, SQL concatenation, shell exec with dynamic input).
- **Dependencies** - `npm audit` / `pip-audit` integration (detailed mode).
- **Config/infra** - unprotected `.env`, Dockerfiles running as root, privileged containers,
  `.git` exposed in a web root.
- **Live web checks** - missing `Strict-Transport-Security`/`Content-Security-Policy`/
  `X-Content-Type-Options`/frame protection/`Referrer-Policy`/`Permissions-Policy`, server/framework
  version disclosure, dangerous CORS configuration, cookie flags (`Secure`/`HttpOnly`/`SameSite`),
  TLS certificate expiry/protocol version, and common exposed paths (`.env`, `.git/config`, backup
  config files, etc.) in detailed mode.

## Quick vs. Detailed

| | Quick | Detailed |
|---|---|---|
| Secrets + code pattern scan | Up to 300 files | All files |
| Dependency audit (npm/pip) | - | Yes |
| Config/infra checks | Yes | Yes |
| Web: headers, cookies, HTTPS | Yes | Yes |
| Web: TLS certificate check | - | Yes |
| Web: common exposed-path probe | - | Yes |

## History: monthly and yearly trend reports

Every scan can be saved to `.secure-checker/history/` in the scanned project, in three tiers so
storage stays bounded no matter how many years you keep scanning:

```
.secure-checker/history/
  raw/      one full ScanResult JSON per scan (all findings) - kept for rawRetentionDays (default 90)
  monthly/  one compact summary per closed month (trend points + new/resolved rule IDs),
            created once that month's raw scans age out - kept for monthlyRetentionMonths (default 24)
  yearly/   one compact summary per closed year (per-month totals + net change),
            created once that year's monthly summaries age out - kept indefinitely
```

- `secure-checker history monthly` / `history yearly` build (or read back, if already compacted) a
  trend report for a given month/year.
- `secure-checker history rollup` compacts anything old enough right now; `scan`/`scan-web` also run
  it automatically after saving history, so it's self-maintaining - you don't need to schedule it.
- Both retention windows are configurable (`--raw-retention-days`, `--monthly-retention-months` on
  the CLI; `secureChecker.rawRetentionDays`/`secureChecker.monthlyRetentionMonths` in VS Code).

This tiering is what makes "keep data for months/years" viable long-term: full per-finding detail
is only needed for recent scans (debugging, diffing), while a year-over-year view only needs
per-month totals. It's also the natural seam for a future hosted/advanced tier - the same
`HistoryStore`-shaped functions (`saveScanToHistory`/`loadRawHistory`/`loadMonthlyRecord`/
`loadYearlyRecord`) could be backed by a database or a sync API instead of local JSON files without
changing any call site in the CLI or editor extension.

The browser extension keeps its own (uncompacted, capped at 500 entries) history in
`chrome.storage.local`, since a single site's header/cookie checks produce far less data per scan.

## CLI usage

```bash
npm install
npm run build

# Scan a codebase
node packages/cli/bin/secure-checker.js scan ./my-project --mode detailed --format html -o report.html

# Scan a live website
node packages/cli/bin/secure-checker.js scan-web https://example.com --mode detailed --format markdown

# Build a monthly / yearly trend report from local history
node packages/cli/bin/secure-checker.js history monthly --project ./my-project --month 2026-10
node packages/cli/bin/secure-checker.js history yearly --project ./my-project --year 2026

# Compact old history now (normally runs automatically after each scan)
node packages/cli/bin/secure-checker.js history rollup --project ./my-project
```

`scan`/`scan-web` exit with code `1` when any critical/high finding is present, so they can gate CI.

To install the CLI globally: `npm link` inside `packages/cli` (after building).

## VS Code extension

```bash
cd packages/vscode-extension
npm run build
```

Open the repo root in VS Code and press F5 (uses `.vscode/launch.json`) to launch an Extension
Development Host. Commands (Cmd/Ctrl+Shift+P):

- **Secure Checker: Quick Scan Workspace**
- **Secure Checker: Detailed Scan Workspace**
- **Secure Checker: Scan Current File**
- **Secure Checker: Scan a Website URL**
- **Secure Checker: Show Monthly Trend Report**
- **Secure Checker: Show Yearly Trend Report**

Findings appear both in the Problems panel (as diagnostics on the relevant file/line) and in a
full HTML report webview. The extension is bundled with esbuild into a single self-contained
`dist/extension.js` (core inlined, only `vscode` stays external), so the packaged `.vsix` needs no
`node_modules`. Build the installable package with:

```bash
npm run package:vscode   # -> packages/vscode-extension/secure-checker.vsix
```

Install it locally via the Extensions view's "Install from VSIX..." command, or `code --install-extension packages/vscode-extension/secure-checker.vsix`.

## Browser extension (Chrome/Edge, Manifest V3)

```bash
cd packages/web-extension
npm run build
```

Then load it unpacked: `chrome://extensions` → Developer mode → "Load unpacked" → select
`packages/web-extension`. Click the toolbar icon on any site and choose Quick or Detailed scan.

To build the distributable package for the Chrome Web Store / Edge Add-ons:

```bash
npm run package:web-extension   # -> packages/web-extension/dist-zip/secure-checker-extension.zip
```

## Development

```bash
npm install        # install all workspace dependencies
npm run build       # build every package
npm run build:core  # build just the engine
npm run test:core   # run the engine's test suite (node:test, 26 tests)
```

The engine (`packages/core`) is published as ESM. It also exposes browser-safe subpath exports
(`@secure-checker/core/web-rules`, `/web-probe`, `/report-html`, `/report-markdown`, `/types`) that
have zero Node.js dependencies, which is what the browser extension bundles via esbuild - the
Node-only pieces (filesystem walking, `npm audit`/`pip-audit` shelling out, TLS socket inspection)
never ship to the browser.
