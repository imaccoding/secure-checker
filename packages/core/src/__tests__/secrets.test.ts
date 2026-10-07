import { test } from "node:test";
import assert from "node:assert/strict";
import { scanTextForSecrets } from "../rules/secrets.js";

test("detects a hardcoded AWS access key", () => {
  const findings = scanTextForSecrets("app.js", `const key = "AKIAABCDEFGHIJKLMNOP";`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "secret-aws-access-key");
  assert.equal(findings[0].severity, "critical");
  assert.equal(findings[0].line, 1);
});

test("detects a generic hardcoded password assignment", () => {
  const findings = scanTextForSecrets("config.js", `const password = "SuperSecret123!";`);
  assert.ok(findings.some((f) => f.ruleId === "secret-generic-password"));
});

test("masks the actual secret value in the reported snippet", () => {
  const findings = scanTextForSecrets("app.js", `const key = "AKIAABCDEFGHIJKLMNOP";`);
  assert.ok(!findings[0].snippet?.includes("AKIAABCDEFGHIJKLMNOP"), "raw secret must not appear in the snippet");
});

test("does not flag ordinary code with no secrets", () => {
  const findings = scanTextForSecrets("app.js", `function add(a, b) { return a + b; }`);
  assert.equal(findings.length, 0);
});

test("detects a database connection string with embedded credentials", () => {
  const findings = scanTextForSecrets("db.js", `const uri = "postgres://admin:hunter2@db.internal:5432/app";`);
  assert.ok(findings.some((f) => f.ruleId === "secret-db-connection-string"));
});
