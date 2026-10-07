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

interface ProbeOutcome {
  status: number;
  signature: string;
}

/** A random, essentially-guaranteed-nonexistent path, used to fingerprint how this server
 * responds to "not found" - many SPAs (React Router, Vite, etc.) route every unmatched path
 * to index.html with a 200 status instead of a real 404, which would otherwise make every
 * exposure check below look like a hit. */
function randomMissingPath(): string {
  return `/__secure-checker-probe-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

async function probe(url: string, fetchImpl: typeof fetch): Promise<ProbeOutcome | undefined> {
  try {
    const res = await fetchImpl(url, { method: "GET", redirect: "manual" });
    let body = "";
    try {
      body = await res.text();
    } catch {
      // unreadable body - fall back to status-only comparison
    }
    return { status: res.status, signature: `${body.length}:${body.slice(0, 200)}` };
  } catch {
    return undefined;
  }
}

export async function probeCommonExposures(baseUrl: string, fetchImpl: typeof fetch = fetch): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = baseUrl.replace(/\/$/, "");

  const baseline = await probe(base + randomMissingPath(), fetchImpl);

  function isDistinguishableFromMissing(outcome: ProbeOutcome | undefined): boolean {
    if (!outcome) return false;
    if (outcome.status < 200 || outcome.status >= 300) return false;
    if (baseline && baseline.status === outcome.status && baseline.signature === outcome.signature) {
      // Same status and body as a guaranteed-missing path - this server returns a catch-all
      // response (SPA fallback, custom error page, etc.) rather than genuinely serving the file.
      return false;
    }
    return true;
  }

  await Promise.all(
    EXPOSURE_PATHS.map(async (exposure) => {
      const url = base + exposure.path;
      const outcome = await probe(url, fetchImpl);
      const isSecurityTxtCheck = exposure.ruleId === "web-missing-security-txt";
      const found = isDistinguishableFromMissing(outcome);

      if (isSecurityTxtCheck && !found) {
        findings.push(toFinding(exposure, url));
      } else if (!isSecurityTxtCheck && found) {
        findings.push(toFinding(exposure, url));
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
