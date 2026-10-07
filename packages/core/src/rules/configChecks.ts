import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join, basename } from "node:path";
import type { Finding } from "../types.js";

/** File-scoped checks that run once per matched config/infra file (as opposed to line-pattern rules). */
export async function scanConfigFile(filePath: string, content: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const name = basename(filePath);

  if (name === "Dockerfile") {
    findings.push(...checkDockerfile(filePath, content));
  }
  if (name === "docker-compose.yml" || name === "docker-compose.yaml") {
    findings.push(...checkDockerCompose(filePath, content));
  }
  if (name === ".env") {
    findings.push(...checkEnvFile(filePath, content));
  }

  return findings;
}

function checkDockerfile(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const hasUser = /^\s*USER\s+(?!root\b)/m.test(content);
  if (!hasUser) {
    findings.push({
      ruleId: "config-dockerfile-root-user",
      title: "Container runs as root",
      severity: "medium",
      category: "config",
      description: "No non-root USER instruction found in the Dockerfile; the container will run as root by default.",
      remediation: "Add a dedicated non-root user (e.g. `RUN adduser -D appuser` then `USER appuser`) before the final CMD/ENTRYPOINT.",
      file: filePath,
    });
  }

  if (/ADD\s+https?:\/\//.test(content)) {
    findings.push({
      ruleId: "config-dockerfile-add-remote-url",
      title: "ADD used to fetch a remote URL",
      severity: "low",
      category: "config",
      description: "ADD with a remote URL skips integrity checking that a separate download+verify step would have.",
      remediation: "Use curl/wget with checksum verification in a RUN step instead of ADD for remote resources.",
      file: filePath,
    });
  }

  if (/--no-check-certificate|curl\s+(-k|--insecure)|wget\s+--no-check-certificate/.test(content)) {
    findings.push({
      ruleId: "config-dockerfile-insecure-download",
      title: "TLS verification disabled during build",
      severity: "high",
      category: "config",
      description: "The Dockerfile disables TLS certificate verification for a download, enabling MITM tampering of fetched content.",
      remediation: "Remove --insecure/--no-check-certificate flags and fix the underlying certificate problem.",
      file: filePath,
    });
  }

  return findings;
}

function checkDockerCompose(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  if (/privileged:\s*true/.test(content)) {
    findings.push({
      ruleId: "config-compose-privileged",
      title: "Privileged container",
      severity: "high",
      category: "config",
      description: "privileged: true grants the container near-full access to the host, defeating container isolation.",
      remediation: "Remove privileged: true; grant only the specific Linux capabilities the container needs via cap_add.",
      file: filePath,
    });
  }
  if (/ports:\s*\n(\s*-\s*["']?0\.0\.0\.0:)/.test(content)) {
    findings.push({
      ruleId: "config-compose-exposed-all-interfaces",
      title: "Port bound to all interfaces",
      severity: "low",
      category: "config",
      description: "A port is explicitly bound to 0.0.0.0, exposing the service on every network interface.",
      remediation: "Bind to 127.0.0.1 for local-only services, or restrict via firewall/security group rules if it must be reachable externally.",
      file: filePath,
    });
  }
  return findings;
}

function checkEnvFile(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  if (content.trim().length > 0) {
    findings.push({
      ruleId: "config-env-file-present",
      title: ".env file with values present in the scanned tree",
      severity: "medium",
      category: "config",
      description: "A .env file containing configuration (and possibly secrets) exists in the project. If committed to version control, its contents are exposed to anyone with repo access.",
      remediation: "Ensure .env is listed in .gitignore and was never committed; rotate any credentials it contains if it has been pushed to a remote repository.",
      file: filePath,
    });
  }
  return findings;
}

/** Project-level checks that don't correspond to a single matched file (e.g. "is .env gitignored?"). */
export async function scanProjectConfig(rootDir: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const envPath = join(rootDir, ".env");
  const gitignorePath = join(rootDir, ".gitignore");
  if (existsSync(envPath)) {
    let gitignored = false;
    if (existsSync(gitignorePath)) {
      const gi = await readFile(gitignorePath, "utf8").catch(() => "");
      gitignored = /(^|\n)\s*\.env\s*($|\n)/.test(gi) || /(^|\n)\s*\*\.env\s*($|\n)/.test(gi);
    }
    if (!gitignored) {
      findings.push({
        ruleId: "config-env-not-gitignored",
        title: ".env is not excluded by .gitignore",
        severity: "high",
        category: "config",
        description: ".env exists but is not covered by .gitignore, risking accidental commit of secrets.",
        remediation: "Add `.env` to .gitignore, and if it was ever committed, remove it from git history and rotate every credential it contained.",
        file: ".env",
      });
    }
  }

  const gitDir = join(rootDir, ".git");
  // Only relevant for web roots served statically, but harmless to flag when scanning a codebase too.
  if (existsSync(join(rootDir, "public", ".git")) || existsSync(join(rootDir, "www", ".git"))) {
    findings.push({
      ruleId: "config-git-dir-in-webroot",
      title: ".git directory inside a public web root",
      severity: "critical",
      category: "config",
      description: "A .git directory under a publicly served folder can leak full source history to anyone who requests it.",
      remediation: "Remove .git from any publicly served directory, or exclude it at the web server level.",
      file: gitDir,
    });
  }

  return findings;
}
