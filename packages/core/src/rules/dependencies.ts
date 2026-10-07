import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding, Severity } from "../types.js";

const execFileAsync = promisify(execFile);

function npmSeverityToOurs(sev: string): Severity {
  switch (sev) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

interface NpmAuditAdvisory {
  module_name?: string;
  name?: string;
  severity: string;
  title: string;
  url?: string;
  range?: string;
  vulnerable_versions?: string;
}

/** Runs `npm audit --json` if a package.json/lockfile is present. Fails soft (returns []) if npm/audit is unavailable. */
export async function scanNpmDependencies(rootDir: string): Promise<Finding[]> {
  if (!existsSync(join(rootDir, "package.json"))) return [];

  try {
    const { stdout } = await execFileAsync("npm", ["audit", "--json"], {
      cwd: rootDir,
      maxBuffer: 20 * 1024 * 1024,
    });
    return parseNpmAuditJson(stdout);
  } catch (err: any) {
    // `npm audit` exits non-zero when vulnerabilities are found; stdout still has the JSON report.
    if (err?.stdout) {
      try {
        return parseNpmAuditJson(err.stdout);
      } catch {
        return [];
      }
    }
    return [];
  }
}

function parseNpmAuditJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  let data: any;
  try {
    data = JSON.parse(stdout);
  } catch {
    return findings;
  }

  // npm v7+ format: data.vulnerabilities is a map of packageName -> { severity, via: [...] }
  if (data.vulnerabilities && typeof data.vulnerabilities === "object") {
    for (const [pkgName, info] of Object.entries<any>(data.vulnerabilities)) {
      const severity = npmSeverityToOurs(info.severity ?? "info");
      const advisories: string[] = [];
      const refs: string[] = [];
      if (Array.isArray(info.via)) {
        for (const via of info.via) {
          if (typeof via === "object" && via !== null) {
            if (via.title) advisories.push(via.title);
            if (via.url) refs.push(via.url);
          }
        }
      }
      findings.push({
        ruleId: "dependency-npm-vulnerable",
        title: `Vulnerable dependency: ${pkgName}`,
        severity,
        category: "dependency",
        description:
          advisories.length > 0
            ? `${pkgName} has known vulnerabilities: ${advisories.slice(0, 3).join("; ")}`
            : `${pkgName} has known vulnerabilities per npm audit (severity: ${info.severity}).`,
        remediation: info.fixAvailable
          ? `Run "npm audit fix" (or update ${pkgName} to a patched version) to resolve this.`
          : `Review the advisory and update ${pkgName}; no automatic fix is currently available, consider an alternative package if the maintainer hasn't patched it.`,
        file: "package.json",
        references: refs.slice(0, 5),
      });
    }
    return findings;
  }

  // Legacy npm v6 format: data.advisories is a map of id -> advisory
  if (data.advisories && typeof data.advisories === "object") {
    for (const advisory of Object.values<NpmAuditAdvisory>(data.advisories)) {
      findings.push({
        ruleId: "dependency-npm-vulnerable",
        title: `Vulnerable dependency: ${advisory.module_name ?? advisory.name ?? "unknown"}`,
        severity: npmSeverityToOurs(advisory.severity),
        category: "dependency",
        description: advisory.title,
        remediation: "Run \"npm audit fix\" or update to a patched version.",
        file: "package.json",
        references: advisory.url ? [advisory.url] : [],
      });
    }
  }

  return findings;
}

/** Runs `pip-audit -f json` if requirements.txt/pyproject.toml is present and pip-audit is installed. Fails soft otherwise. */
export async function scanPythonDependencies(rootDir: string): Promise<Finding[]> {
  const hasReqs = existsSync(join(rootDir, "requirements.txt")) || existsSync(join(rootDir, "pyproject.toml"));
  if (!hasReqs) return [];

  try {
    const { stdout } = await execFileAsync("pip-audit", ["-f", "json"], {
      cwd: rootDir,
      maxBuffer: 20 * 1024 * 1024,
    });
    return parsePipAuditJson(stdout);
  } catch (err: any) {
    if (err?.stdout) {
      try {
        return parsePipAuditJson(err.stdout);
      } catch {
        return [];
      }
    }
    // pip-audit not installed, or no network - fail soft; the quick/detailed scan still succeeds.
    return [];
  }
}

function parsePipAuditJson(stdout: string): Finding[] {
  const findings: Finding[] = [];
  let data: any;
  try {
    data = JSON.parse(stdout);
  } catch {
    return findings;
  }
  const deps = Array.isArray(data) ? data : data.dependencies ?? [];
  for (const dep of deps) {
    const vulns = dep.vulns ?? dep.vulnerabilities ?? [];
    for (const vuln of vulns) {
      findings.push({
        ruleId: "dependency-pip-vulnerable",
        title: `Vulnerable dependency: ${dep.name}@${dep.version}`,
        severity: "high",
        category: "dependency",
        description: `${dep.name} ${dep.version} is affected by ${vuln.id ?? "a known vulnerability"}${
          vuln.description ? `: ${vuln.description.slice(0, 200)}` : ""
        }`,
        remediation: vuln.fix_versions?.length
          ? `Upgrade ${dep.name} to ${vuln.fix_versions.join(" or ")}.`
          : `Review the advisory ${vuln.id ?? ""} and update ${dep.name} when a fix is available.`,
        file: "requirements.txt",
        references: vuln.id ? [`https://osv.dev/vulnerability/${vuln.id}`] : [],
      });
    }
  }
  return findings;
}
