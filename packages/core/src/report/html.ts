import type { ScanResult, Finding, Severity } from "../types.js";

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#7f1d1d",
  high: "#b91c1c",
  medium: "#b45309",
  low: "#1d4ed8",
  info: "#374151",
};

function esc(input: unknown): string {
  return String(input ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function toHtml(result: ScanResult): string {
  const rows = result.findings.map(findingHtml).join("\n");
  const s = result.summary;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Secure Checker Report - ${esc(result.target)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem; background: #0b0f14; color: #e5e7eb; }
  @media (prefers-color-scheme: light) { body { background: #f8fafc; color: #111827; } }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #9ca3af; font-size: 0.9rem; margin-bottom: 1.5rem; }
  .summary { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .pill { padding: 0.4rem 0.9rem; border-radius: 999px; font-weight: 600; font-size: 0.85rem; color: #fff; }
  .finding { border: 1px solid #27303f; border-left-width: 6px; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; background: rgba(255,255,255,0.03); }
  .finding h3 { margin: 0 0 0.4rem 0; }
  .badge { display: inline-block; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em; padding: 0.15rem 0.5rem; border-radius: 4px; color: #fff; margin-right: 0.5rem; }
  .ruleid { font-family: ui-monospace, Consolas, monospace; font-size: 0.8rem; color: #9ca3af; }
  .loc { font-family: ui-monospace, Consolas, monospace; font-size: 0.85rem; color: #93c5fd; }
  pre { background: #0f172a; color: #e2e8f0; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
  .remediation { margin-top: 0.6rem; padding: 0.6rem 0.8rem; background: rgba(16,185,129,0.08); border-left: 3px solid #10b981; border-radius: 4px; }
  .remediation strong { color: #10b981; }
  .refs { margin-top: 0.5rem; font-size: 0.85rem; }
  .refs a { color: #60a5fa; }
  .empty { padding: 2rem; text-align: center; color: #10b981; font-size: 1.1rem; }
</style>
</head>
<body>
  <h1>Secure Checker Report</h1>
  <div class="meta">
    Target: <strong>${esc(result.target)}</strong> (${esc(result.targetType)}) &middot;
    Mode: <strong>${esc(result.mode)}</strong> &middot;
    ${esc(result.startedAt)} &rarr; ${esc(result.finishedAt)} (${result.durationMs}ms)
    ${result.filesScanned !== undefined ? ` &middot; Files scanned: ${result.filesScanned}` : ""}
  </div>
  <div class="summary">
    <span class="pill" style="background:${SEVERITY_COLOR.critical}">Critical: ${s.critical}</span>
    <span class="pill" style="background:${SEVERITY_COLOR.high}">High: ${s.high}</span>
    <span class="pill" style="background:${SEVERITY_COLOR.medium}">Medium: ${s.medium}</span>
    <span class="pill" style="background:${SEVERITY_COLOR.low}">Low: ${s.low}</span>
    <span class="pill" style="background:${SEVERITY_COLOR.info}">Info: ${s.info}</span>
  </div>
  ${result.findings.length === 0 ? `<div class="empty">No findings for this scan.</div>` : rows}
</body>
</html>`;
}

function findingHtml(f: Finding): string {
  const color = SEVERITY_COLOR[f.severity];
  const locLine = f.file
    ? `${esc(f.file)}${f.line ? `:${f.line}` : ""}`
    : f.location
      ? esc(f.location)
      : "";

  return `<div class="finding" style="border-left-color:${color}">
    <h3><span class="badge" style="background:${color}">${esc(f.severity.toUpperCase())}</span>${esc(f.title)}</h3>
    <div class="ruleid">${esc(f.ruleId)}</div>
    ${locLine ? `<div class="loc">${locLine}</div>` : ""}
    <p>${esc(f.description)}</p>
    ${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ""}
    <div class="remediation"><strong>Fix:</strong> ${esc(f.remediation)}</div>
    ${
      f.references?.length
        ? `<div class="refs">${f.references.map((r) => `<a href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a>`).join("<br/>")}</div>`
        : ""
    }
  </div>`;
}
