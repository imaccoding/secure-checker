import type { ScanResult, Finding, Severity } from "../types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function toMarkdown(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`# Secure Checker Report`);
  lines.push("");
  lines.push(`- **Target:** ${result.target} (${result.targetType})`);
  lines.push(`- **Mode:** ${result.mode}`);
  lines.push(`- **Scanned:** ${result.startedAt} → ${result.finishedAt} (${result.durationMs}ms)`);
  if (result.filesScanned !== undefined) lines.push(`- **Files scanned:** ${result.filesScanned}`);
  lines.push("");
  lines.push(
    `**Summary:** ${result.summary.total} finding(s) — ` +
      `${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low, ${result.summary.info} info`
  );
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings. 🎉");
    return lines.join("\n");
  }

  for (const f of result.findings) {
    lines.push(`## [${SEVERITY_LABEL[f.severity]}] ${f.title}`);
    lines.push("");
    lines.push(`- **Rule:** \`${f.ruleId}\``);
    if (f.file) lines.push(`- **File:** ${f.file}${f.line ? `:${f.line}` : ""}`);
    if (f.location) lines.push(`- **Location:** ${f.location}`);
    lines.push("");
    lines.push(f.description);
    lines.push("");
    if (f.snippet) {
      lines.push("```");
      lines.push(f.snippet);
      lines.push("```");
      lines.push("");
    }
    lines.push(`**Remediation:** ${f.remediation}`);
    if (f.references?.length) {
      lines.push("");
      lines.push("References:");
      for (const ref of f.references) lines.push(`- ${ref}`);
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  return lines.join("\n");
}
