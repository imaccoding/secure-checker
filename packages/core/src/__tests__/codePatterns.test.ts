import { test } from "node:test";
import assert from "node:assert/strict";
import { scanTextForCodePatterns } from "../rules/codePatterns.js";

test("detects eval() in a JS file", () => {
  const findings = scanTextForCodePatterns("app.js", `eval(userInput);`);
  assert.ok(findings.some((f) => f.ruleId === "code-js-eval"));
});

test("detects SQL injection via string concatenation", () => {
  const findings = scanTextForCodePatterns("app.js", `db.query("SELECT * FROM users WHERE id = " + userInput);`);
  assert.ok(findings.some((f) => f.ruleId === "code-js-sql-concat"));
});

test("detects disabled TLS verification", () => {
  const findings = scanTextForCodePatterns("app.js", `const agent = new https.Agent({ rejectUnauthorized: false });`);
  assert.ok(findings.some((f) => f.ruleId === "code-js-insecure-tls"));
});

test("detects pickle.loads in Python but not in a .js file", () => {
  const py = scanTextForCodePatterns("app.py", `data = pickle.loads(raw)`);
  assert.ok(py.some((f) => f.ruleId === "code-py-pickle-loads"));

  const js = scanTextForCodePatterns("app.js", `data = pickle.loads(raw)`);
  assert.ok(!js.some((f) => f.ruleId === "code-py-pickle-loads"), "Python-only rules must not fire on .js files");
});

test("detects shell=True in subprocess calls", () => {
  const findings = scanTextForCodePatterns("run.py", `subprocess.run(cmd, shell=True)`);
  assert.ok(findings.some((f) => f.ruleId === "code-py-subprocess-shell-true"));
});

test("detects unserialize() in PHP", () => {
  const findings = scanTextForCodePatterns("app.php", `$data = unserialize($_GET['payload']);`);
  assert.ok(findings.some((f) => f.ruleId === "code-php-unserialize"));
});

test("does not flag safe, parameterized code", () => {
  const findings = scanTextForCodePatterns(
    "app.js",
    `db.query("SELECT * FROM users WHERE id = ?", [userId]);\nconst agent = new https.Agent({ rejectUnauthorized: true });`
  );
  assert.equal(findings.length, 0);
});
