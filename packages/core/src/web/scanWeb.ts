import { evaluateSecurityHeaders, evaluateCookies } from "./rules.js";
import { checkTls } from "./tlsCheck.js";
import { probeCommonExposures } from "./probePaths.js";
import { summarize, sortFindings, type ScanMode, type ScanResult, type Finding } from "../types.js";

export interface ScanWebOptions {
  mode: ScanMode;
  onProgress?: (message: string) => void;
}

/** Node-only orchestrator: full detailed web scan including TLS cert check and common exposed-path probing. */
export async function scanWebsite(targetUrl: string, options: ScanWebOptions): Promise<ScanResult> {
  const startedAt = new Date();
  const { mode, onProgress } = options;
  const url = normalizeUrl(targetUrl);
  const findings: Finding[] = [];

  onProgress?.(`Fetching ${url}...`);
  try {
    const res = await fetch(url, { redirect: "follow" });
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    findings.push(...evaluateSecurityHeaders({ url, headers }));

    const setCookie = getSetCookieHeaders(res.headers);
    if (setCookie.length > 0) {
      findings.push(...evaluateCookies({ url, setCookieHeaders: setCookie }));
    }

    if (url.startsWith("http://")) {
      findings.push({
        ruleId: "web-no-https",
        title: "Site served over plain HTTP",
        severity: "high",
        category: "web-tls",
        description: "The site does not use HTTPS, so all traffic (including any credentials) is unencrypted and tamperable in transit.",
        remediation: "Serve the site exclusively over HTTPS and redirect all HTTP requests to HTTPS.",
        location: url,
      });
    }
  } catch (err: any) {
    findings.push({
      ruleId: "web-unreachable",
      title: "Target was unreachable",
      severity: "info",
      category: "web-header",
      description: `Could not fetch ${url}: ${err?.message ?? "unknown error"}`,
      remediation: "Verify the URL is correct and reachable from this network.",
      location: url,
    });
  }

  if (mode === "detailed") {
    const hostname = new URL(url).hostname;
    onProgress?.("Checking TLS certificate...");
    if (url.startsWith("https://")) {
      findings.push(...(await checkTls(hostname)));
    }
    onProgress?.("Probing common exposed paths...");
    findings.push(...(await probeCommonExposures(url)));
  }

  const finishedAt = new Date();
  const sorted = sortFindings(findings);

  return {
    target: url,
    targetType: "website",
    mode,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    findings: sorted,
    summary: summarize(sorted),
  };
}

function normalizeUrl(input: string): string {
  if (!/^https?:\/\//i.test(input)) {
    return `https://${input}`;
  }
  return input;
}

function getSetCookieHeaders(headers: Headers): string[] {
  // Node's undici Headers supports getSetCookie(); fall back for other runtimes.
  const anyHeaders = headers as any;
  if (typeof anyHeaders.getSetCookie === "function") {
    return anyHeaders.getSetCookie();
  }
  const single = headers.get("set-cookie");
  return single ? [single] : [];
}
