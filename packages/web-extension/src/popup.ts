import type { Finding, ScanMode, ScanResult, Severity } from "@secure-checker/core/types";

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#7f1d1d",
  high: "#b91c1c",
  medium: "#b45309",
  low: "#1d4ed8",
  info: "#374151",
};

const targetUrlEl = document.getElementById("targetUrl")!;
const statusEl = document.getElementById("status")!;
const summaryEl = document.getElementById("summary")!;
const findingsEl = document.getElementById("findings")!;
const quickBtn = document.getElementById("quickScanBtn") as HTMLButtonElement;
const detailedBtn = document.getElementById("detailedScanBtn") as HTMLButtonElement;

let currentUrl = "";

init();

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentUrl = tab?.url ?? "";
  targetUrlEl.textContent = currentUrl || "No active tab URL";

  const scannable = /^https?:\/\//.test(currentUrl);
  quickBtn.disabled = !scannable;
  detailedBtn.disabled = !scannable;
  if (!scannable) {
    statusEl.textContent = "This page can't be scanned (not an http/https URL).";
  }

  quickBtn.addEventListener("click", () => runScan("quick"));
  detailedBtn.addEventListener("click", () => runScan("detailed"));
}

async function runScan(mode: ScanMode) {
  setBusy(true);
  statusEl.textContent = mode === "quick" ? "Running quick scan..." : "Running detailed scan (checking common exposed paths too)...";
  summaryEl.replaceChildren();
  findingsEl.replaceChildren();

  chrome.runtime.sendMessage({ type: "SCAN", url: currentUrl, mode }, (response) => {
    setBusy(false);
    if (chrome.runtime.lastError) {
      statusEl.textContent = `Error: ${chrome.runtime.lastError.message}`;
      return;
    }
    if (!response?.ok) {
      statusEl.textContent = `Error: ${response?.error ?? "scan failed"}`;
      return;
    }
    statusEl.textContent = "";
    renderResult(response.result as ScanResult);
  });
}

function setBusy(busy: boolean) {
  quickBtn.disabled = busy;
  detailedBtn.disabled = busy;
}

function renderResult(result: ScanResult) {
  renderSummary(result);
  if (result.findings.length === 0) {
    const div = document.createElement("div");
    div.className = "empty";
    div.textContent = "No findings for this scan.";
    findingsEl.appendChild(div);
    return;
  }
  for (const f of result.findings) {
    findingsEl.appendChild(renderFinding(f));
  }
}

function renderSummary(result: ScanResult) {
  const s = result.summary;
  const entries: [string, number][] = [
    ["Critical", s.critical],
    ["High", s.high],
    ["Medium", s.medium],
    ["Low", s.low],
    ["Info", s.info],
  ];
  for (const [label, count] of entries) {
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.style.background = SEVERITY_COLOR[label.toLowerCase() as Severity];
    pill.textContent = `${label}: ${count}`;
    summaryEl.appendChild(pill);
  }
}

function renderFinding(f: Finding): HTMLElement {
  const div = document.createElement("div");
  div.className = "finding";
  div.style.borderLeftColor = SEVERITY_COLOR[f.severity];

  const title = document.createElement("div");
  title.className = "title";
  title.textContent = `[${f.severity.toUpperCase()}] ${f.title}`;
  div.appendChild(title);

  const desc = document.createElement("div");
  desc.className = "desc";
  desc.textContent = f.description;
  div.appendChild(desc);

  const fix = document.createElement("div");
  fix.className = "fix";
  fix.textContent = `Fix: ${f.remediation}`;
  div.appendChild(fix);

  return div;
}
