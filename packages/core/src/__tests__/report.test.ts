import { test } from "node:test";
import assert from "node:assert/strict";
import { toHtml } from "../report/html.js";
import { toMarkdown } from "../report/markdown.js";
import { summarize, sortFindings, type Finding, type ScanResult } from "../types.js";

function makeResult(findings: Finding[]): ScanResult {
  const sorted = sortFindings(findings);
  return {
    target: "/tmp/project",
    targetType: "codebase",
    mode: "quick",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    findings: sorted,
    summary: summarize(sorted),
  };
}

test("HTML report escapes attacker-controlled content from scanned files", () => {
  const malicious: Finding = {
    ruleId: "code-generic-http-url",
    title: "Hardcoded plaintext HTTP URL",
    severity: "low",
    category: "code",
    description: "found it",
    remediation: "fix it",
    file: "<img src=x onerror=alert(1)>.js",
    snippet: `<script>alert('xss-from-scanned-file')</script>`,
  };
  const html = toHtml(makeResult([malicious]));
  assert.ok(!html.includes("<script>alert"), "raw script tag from scanned content must not appear unescaped");
  assert.ok(!html.includes("<img src=x"), "raw img tag with an event handler from a filename must not appear unescaped");
  assert.ok(html.includes("&lt;script&gt;"), "escaped version of the snippet should be present");
  assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;"), "escaped version of the filename should be present");
});

test("HTML report renders severity pills with correct summary counts", () => {
  const html = toHtml(
    makeResult([
      { ruleId: "a", title: "A", severity: "critical", category: "secret", description: "d", remediation: "r" },
      { ruleId: "b", title: "B", severity: "high", category: "code", description: "d", remediation: "r" },
    ])
  );
  assert.ok(html.includes("Critical: 1"));
  assert.ok(html.includes("High: 1"));
  assert.ok(html.includes("Medium: 0"));
});

test("empty findings renders a clean 'no findings' state", () => {
  const html = toHtml(makeResult([]));
  assert.ok(html.includes("No findings"));
});

test("markdown report includes rule id and remediation for each finding", () => {
  const md = toMarkdown(
    makeResult([
      { ruleId: "secret-aws-access-key", title: "AWS key", severity: "critical", category: "secret", description: "d", remediation: "rotate it", file: "a.js", line: 5 },
    ])
  );
  assert.ok(md.includes("secret-aws-access-key"));
  assert.ok(md.includes("rotate it"));
  assert.ok(md.includes("a.js:5"));
});
