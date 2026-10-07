import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateSecurityHeaders, evaluateCookies } from "../web/rules.js";

test("flags missing security headers", () => {
  const findings = evaluateSecurityHeaders({ url: "https://example.com", headers: {} });
  const ruleIds = findings.map((f) => f.ruleId);
  assert.ok(ruleIds.includes("web-missing-hsts"));
  assert.ok(ruleIds.includes("web-missing-csp"));
  assert.ok(ruleIds.includes("web-missing-xcto"));
  assert.ok(ruleIds.includes("web-missing-frame-protection"));
});

test("does not flag headers that are present", () => {
  const findings = evaluateSecurityHeaders({
    url: "https://example.com",
    headers: {
      "strict-transport-security": "max-age=31536000",
      "content-security-policy": "default-src 'self'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "geolocation=()",
    },
  });
  const ruleIds = findings.map((f) => f.ruleId);
  assert.ok(!ruleIds.includes("web-missing-hsts"));
  assert.ok(!ruleIds.includes("web-missing-csp"));
  assert.ok(!ruleIds.includes("web-missing-frame-protection"));
});

test("flags dangerous wildcard CORS with credentials", () => {
  const findings = evaluateSecurityHeaders({
    url: "https://example.com",
    headers: { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" },
  });
  assert.ok(findings.some((f) => f.ruleId === "web-cors-wildcard-with-credentials" && f.severity === "critical"));
});

test("flags a cookie missing Secure on an https page", () => {
  const findings = evaluateCookies({ url: "https://example.com", setCookieHeaders: ["session=abc123; Path=/"] });
  assert.ok(findings.some((f) => f.ruleId === "web-cookie-missing-secure"));
});

test("flags a session-like cookie missing HttpOnly", () => {
  const findings = evaluateCookies({ url: "https://example.com", setCookieHeaders: ["sessionid=abc123; Secure"] });
  assert.ok(findings.some((f) => f.ruleId === "web-cookie-missing-httponly"));
});

test("does not flag a fully-hardened cookie", () => {
  const findings = evaluateCookies({
    url: "https://example.com",
    setCookieHeaders: ["sessionid=abc123; Secure; HttpOnly; SameSite=Strict"],
  });
  assert.equal(findings.length, 0);
});
