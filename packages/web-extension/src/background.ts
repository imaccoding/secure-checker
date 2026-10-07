import { evaluateSecurityHeaders, evaluateCookies } from "@secure-checker/core/web-rules";
import { probeCommonExposures } from "@secure-checker/core/web-probe";
import { summarize, sortFindings } from "@secure-checker/core/types";
import type { Finding, ScanMode, ScanResult } from "@secure-checker/core/types";

const HISTORY_KEY = "secureChecker.history";
const MAX_HISTORY_ENTRIES = 500;

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN") {
    scanUrl(message.url as string, message.mode as ScanMode)
      .then(async (result) => {
        await appendHistory(result);
        sendResponse({ ok: true, result });
      })
      .catch((err) => sendResponse({ ok: false, error: String(err?.message ?? err) }));
    return true; // keep the message channel open for the async response
  }
  if (message?.type === "GET_HISTORY") {
    getHistory().then((history) => sendResponse({ ok: true, history }));
    return true;
  }
  return undefined;
});

async function scanUrl(targetUrl: string, mode: ScanMode): Promise<ScanResult> {
  const startedAt = new Date();
  const url = targetUrl;
  const findings: Finding[] = [];

  const res = await fetch(url, { method: "GET", redirect: "follow" });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  findings.push(...evaluateSecurityHeaders({ url, headers }));

  if (url.startsWith("http://")) {
    findings.push({
      ruleId: "web-no-https",
      title: "Site served over plain HTTP",
      severity: "high",
      category: "web-tls",
      description:
        "The site does not use HTTPS, so all traffic (including any credentials) is unencrypted and tamperable in transit.",
      remediation: "Serve the site exclusively over HTTPS and redirect all HTTP requests to HTTPS.",
      location: url,
    });
  }

  try {
    const cookies = await chrome.cookies.getAll({ url });
    const pseudoSetCookie = cookies.map((c) => {
      const flags = [
        c.secure ? "Secure" : "",
        c.httpOnly ? "HttpOnly" : "",
        c.sameSite && c.sameSite !== "unspecified" ? `SameSite=${c.sameSite}` : "",
      ]
        .filter(Boolean)
        .join("; ");
      return `${c.name}=${c.value}${flags ? "; " + flags : ""}`;
    });
    if (pseudoSetCookie.length > 0) {
      findings.push(...evaluateCookies({ url, setCookieHeaders: pseudoSetCookie }));
    }
  } catch {
    // cookies permission may be unavailable for this URL scheme - skip silently.
  }

  if (mode === "detailed") {
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

async function appendHistory(result: ScanResult): Promise<void> {
  const history = await getHistory();
  history.push(result);
  const trimmed = history.slice(-MAX_HISTORY_ENTRIES);
  await chrome.storage.local.set({ [HISTORY_KEY]: trimmed });
}

async function getHistory(): Promise<ScanResult[]> {
  const stored = await chrome.storage.local.get(HISTORY_KEY);
  return (stored[HISTORY_KEY] as ScanResult[]) ?? [];
}
