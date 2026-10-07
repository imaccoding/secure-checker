export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "secret"
  | "code"
  | "dependency"
  | "config"
  | "web-header"
  | "web-cookie"
  | "web-tls"
  | "web-exposure"
  | "web-cors";

export type ScanMode = "quick" | "detailed";

export interface Finding {
  /** Stable identifier for the rule that produced this finding, e.g. "secret-aws-access-key" */
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  description: string;
  remediation: string;
  /** File path relative to the scan target, when applicable */
  file?: string;
  line?: number;
  snippet?: string;
  /** URL or endpoint, when applicable (web scans) */
  location?: string;
  references?: string[];
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResult {
  target: string;
  targetType: "codebase" | "website";
  mode: ScanMode;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  findings: Finding[];
  summary: ScanSummary;
  filesScanned?: number;
}

export function summarize(findings: Finding[]): ScanSummary {
  const summary: ScanSummary = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    summary[f.severity]++;
  }
  return summary;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
