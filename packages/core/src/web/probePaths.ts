import type { Finding } from "../types.js";

interface ExposurePath {
  path: string;
  ruleId: string;
  title: string;
  severity: Finding["severity"];
  description: string;
  remediation: string;
}

const EXPOSURE_PATHS: ExposurePath[] = [
  {
    path: "/.env",
    ruleId: "web-exposed-env",
    title: "Exposed .env file",
    severity: "critical",
    description: "A .env file is publicly reachable and may contain credentials/secrets.",
    remediation: "Remove .env from the web root / block it at the web server level, and rotate any exposed secrets.",
  },
  {
    path: "/.git/config",
    ruleId: "web-exposed-git",
    title: "Exposed .git directory",
    severity: "critical",
    description: "The .git directory is publicly reachable, allowing full source history to be reconstructed.",
    remediation: "Remove .git from the deployed web root or block access to it at the web server level.",
  },
  {
    path: "/.DS_Store",
    ruleId: "web-exposed-dsstore",
    title: "Exposed .DS_Store file",
    severity: "low",
    description: ".DS_Store can leak a listing of files/directories present on the server at build time.",
    remediation: "Exclude .DS_Store from deployments and block it at the web server level.",
  },
  {
    path: "/wp-config.php.bak",
    ruleId: "web-exposed-backup-config",
    title: "Exposed backup config file",
    severity: "critical",
    description: "A backup configuration file is publicly reachable and likely contains database credentials.",
    remediation: "Remove backup files from the web root and rotate any exposed credentials.",
  },
  {
    path: "/server-status",
    ruleId: "web-exposed-server-status",
    title: "Apache server-status exposed",
    severity: "medium",
    description: "mod_status output is publicly reachable, revealing internal requests, IPs, and server details.",
    remediation: "Restrict /server-status to localhost/trusted IPs in the Apache configuration.",
  },
  {
    path: "/.well-known/security.txt",
    ruleId: "web-missing-security-txt",
    title: "No security.txt found",
    severity: "info",
    description: "No /.well-known/security.txt was found, making it harder for researchers to report vulnerabilities responsibly.",
    remediation: "Publish a security.txt per RFC 9116 with a contact for vulnerability reports.",
  },
];

export async function probeCommonExposures(baseUrl: string, fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = baseUrl.replace(/\/$/, "");

  await Promise.all(
    EXPOSURE_PATHS.map(async (exposure) => {
      const url = base + exposure.path;
      try {
        const res = await fetchImpl(url, { method: "GET", redirect: "manual" });
        const isSecurityTxtCheck = exposure.ruleId === "web-missing-security-txt";
        const found = res.status >= 200 && res.status < 300;

        if (isSecurityTxtCheck && !found) {
          findings.push(toFinding(exposure, url));
        } else if (!isSecurityTxtCheck && found) {
          findings.push(toFinding(exposure, url));
        }
      } catch {
        // Network error / blocked - skip silently, this is a best-effort probe.
      }
    })
  );

  return findings;
}

function toFinding(exposure: ExposurePath, url: string): Finding {
  return {
    ruleId: exposure.ruleId,
    title: exposure.title,
    severity: exposure.severity,
    category: "web-exposure",
    description: exposure.description,
    remediation: exposure.remediation,
    location: url,
  };
}
