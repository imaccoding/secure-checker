import { test } from "node:test";
import assert from "node:assert/strict";
import { probeCommonExposures } from "../web/probePaths.js";

function fakeResponse(status: number, body: string): Response {
  return new Response(body, { status });
}

test("does not report exposed files when the server is a SPA that 200s every path (fallback routing)", async () => {
  const spaIndexHtml = "<!doctype html><html><body>App</body></html>";
  const fetchImpl = (async (_url: string | URL) => fakeResponse(200, spaIndexHtml)) as unknown as typeof fetch;

  const findings = await probeCommonExposures("https://spa.example.com", fetchImpl);

  const falsePositiveRuleIds = ["web-exposed-env", "web-exposed-git", "web-exposed-backup-config", "web-exposed-dsstore", "web-exposed-server-status"];
  for (const ruleId of falsePositiveRuleIds) {
    assert.ok(!findings.some((f) => f.ruleId === ruleId), `${ruleId} must not fire against a catch-all SPA response`);
  }
});

test("still reports a genuinely exposed .env file distinguishable from the 404 baseline", async () => {
  const fetchImpl = (async (url: string | URL) => {
    const s = String(url);
    if (s.endsWith("/.env")) return fakeResponse(200, "DB_PASSWORD=hunter2\nAPI_KEY=abc123");
    return fakeResponse(404, "Not Found");
  }) as unknown as typeof fetch;

  const findings = await probeCommonExposures("https://real-exposure.example.com", fetchImpl);
  assert.ok(findings.some((f) => f.ruleId === "web-exposed-env"));
});

test("reports missing security.txt as an informational finding even behind a SPA fallback", async () => {
  const spaIndexHtml = "<!doctype html><html><body>App</body></html>";
  const fetchImpl = (async () => fakeResponse(200, spaIndexHtml)) as unknown as typeof fetch;

  const findings = await probeCommonExposures("https://spa.example.com", fetchImpl);
  assert.ok(findings.some((f) => f.ruleId === "web-missing-security-txt"));
});
