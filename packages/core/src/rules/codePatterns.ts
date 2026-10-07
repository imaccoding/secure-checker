import { extname } from "node:path";
import type { Finding } from "../types.js";

interface CodeRule {
  ruleId: string;
  title: string;
  pattern: RegExp;
  severity: Finding["severity"];
  description: string;
  remediation: string;
  /** Limit to specific extensions; omit to apply to all scanned text files */
  extensions?: string[];
}

const RULES: CodeRule[] = [
  // --- JavaScript / TypeScript ---
  {
    ruleId: "code-js-eval",
    title: "Use of eval()",
    pattern: /\beval\s*\(/,
    severity: "high",
    description: "eval() executes arbitrary strings as code, which is a common vector for code injection.",
    remediation: "Avoid eval(). Use JSON.parse for data, or restructure the logic to avoid dynamic code execution.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-new-function",
    title: "Dynamic code execution via new Function()",
    pattern: /new\s+Function\s*\(/,
    severity: "high",
    description: "new Function() compiles a string into executable code, similar in risk to eval().",
    remediation: "Avoid constructing functions from strings; use static functions or a safe expression evaluator.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-child-process-concat",
    title: "Possible command injection via child_process",
    pattern: /child_process\.(exec|execSync)\s*\(\s*[`'"].*\$\{|child_process\.(exec|execSync)\s*\([^,)]*\+/,
    severity: "critical",
    description: "A shell command is built using string concatenation/interpolation and passed to exec(), which risks command injection if any part is user-controlled.",
    remediation: "Use execFile()/spawn() with an argument array instead of a shell string, and validate/allowlist any user-supplied input.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-innerhtml",
    title: "Assignment to innerHTML",
    pattern: /\.innerHTML\s*=/,
    severity: "medium",
    description: "Assigning to innerHTML with unsanitized data can lead to DOM-based XSS.",
    remediation: "Use textContent for plain text, or sanitize HTML with a library like DOMPurify before assigning innerHTML.",
    extensions: [".js", ".jsx", ".ts", ".tsx"],
  },
  {
    ruleId: "code-react-dangerously-set-innerhtml",
    title: "dangerouslySetInnerHTML usage",
    pattern: /dangerouslySetInnerHTML/,
    severity: "medium",
    description: "dangerouslySetInnerHTML bypasses React's XSS protections.",
    remediation: "Sanitize any HTML passed here with DOMPurify, or avoid rendering raw HTML entirely.",
    extensions: [".jsx", ".tsx", ".js", ".ts"],
  },
  {
    ruleId: "code-js-document-write",
    title: "Use of document.write()",
    pattern: /document\.write\s*\(/,
    severity: "low",
    description: "document.write() with dynamic content can enable XSS and blocks page rendering.",
    remediation: "Use DOM APIs (createElement/appendChild) or a templating/framework mechanism instead.",
    extensions: [".js", ".jsx", ".ts", ".tsx"],
  },
  {
    ruleId: "code-js-insecure-tls",
    title: "TLS certificate validation disabled",
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/,
    severity: "critical",
    description: "TLS certificate verification is disabled, allowing man-in-the-middle attacks.",
    remediation: "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0. Fix the underlying certificate issue instead of disabling validation.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-weak-random-secret",
    title: "Math.random() used for security-sensitive value",
    pattern: /(token|password|secret|otp|session)[A-Za-z]*\s*=\s*.{0,40}Math\.random\(\)/i,
    severity: "high",
    description: "Math.random() is not cryptographically secure and should not be used to generate tokens, passwords, or session identifiers.",
    remediation: "Use crypto.randomBytes()/crypto.randomUUID() (Node) or the Web Crypto API's crypto.getRandomValues() instead.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-jwt-none-alg",
    title: "JWT verification allows 'none' algorithm",
    pattern: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    severity: "critical",
    description: "Accepting the 'none' algorithm lets an attacker forge unsigned JWTs that pass verification.",
    remediation: "Explicitly allowlist strong algorithms (e.g. RS256/ES256) and never include 'none'.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-cors-wildcard-credentials",
    title: "Wildcard CORS origin",
    pattern: /Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|origin\s*:\s*['"]\*['"]/,
    severity: "medium",
    description: "A wildcard CORS origin allows any website to make cross-origin requests; combined with credentials this can expose authenticated data.",
    remediation: "Return a specific allowlisted origin instead of '*', especially on any endpoint that uses cookies or credentials.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },
  {
    ruleId: "code-js-sql-concat",
    title: "Possible SQL injection via string concatenation",
    pattern: /\.(query|execute)\s*\(\s*[`'"][^`'"]*\$\{|\.(query|execute)\s*\(\s*['"][^'")]*['"]\s*\+/,
    severity: "critical",
    description: "A SQL query is built by concatenating/interpolating variables directly into the query string.",
    remediation: "Use parameterized queries / prepared statements (e.g. placeholders with bound parameters) instead of string concatenation.",
    extensions: [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
  },

  // --- Python ---
  {
    ruleId: "code-py-eval-exec",
    title: "Use of eval()/exec()",
    pattern: /\b(eval|exec)\s*\(/,
    severity: "high",
    description: "eval()/exec() execute arbitrary code and are a common injection vector.",
    remediation: "Avoid eval/exec on dynamic input; use ast.literal_eval for safe data parsing or restructure the logic.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-pickle-loads",
    title: "Untrusted deserialization via pickle",
    pattern: /pickle\.loads?\s*\(/,
    severity: "critical",
    description: "pickle can execute arbitrary code during deserialization of untrusted data.",
    remediation: "Use a safe serialization format (JSON) for untrusted data, or restrict pickle to trusted, signed sources.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-yaml-unsafe-load",
    title: "Unsafe YAML load",
    pattern: /yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)/,
    severity: "high",
    description: "yaml.load() without SafeLoader can instantiate arbitrary Python objects from untrusted YAML.",
    remediation: "Use yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-subprocess-shell-true",
    title: "subprocess call with shell=True",
    pattern: /subprocess\.\w+\([^)]*shell\s*=\s*True/,
    severity: "high",
    description: "shell=True combined with untrusted input risks command injection.",
    remediation: "Pass command arguments as a list with shell=False, and avoid building commands via string concatenation.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-os-system",
    title: "Use of os.system()",
    pattern: /os\.system\s*\(/,
    severity: "high",
    description: "os.system() runs a string through the shell, risking command injection if input is attacker-influenced.",
    remediation: "Use subprocess.run([...], shell=False) with an argument list instead.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-flask-debug-true",
    title: "Flask debug mode enabled",
    pattern: /app\.run\([^)]*debug\s*=\s*True/,
    severity: "high",
    description: "Flask's debugger exposes an interactive Werkzeug console that allows remote code execution if reachable in production.",
    remediation: "Disable debug mode in production (debug=False) and use a proper WSGI server.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-django-debug-true",
    title: "Django DEBUG=True",
    pattern: /^\s*DEBUG\s*=\s*True\s*$/m,
    severity: "high",
    description: "DEBUG=True in Django can leak stack traces, settings, and environment details to visitors.",
    remediation: "Set DEBUG=False in production and configure ALLOWED_HOSTS appropriately.",
    extensions: [".py"],
  },
  {
    ruleId: "code-py-sql-string-format",
    title: "Possible SQL injection via string formatting",
    pattern: /\.(execute|executemany)\s*\(\s*(f['"]|['"].*%s.*['"]\s*%|['"].*\{.*\}['"]\.format)/,
    severity: "critical",
    description: "A SQL query appears to be built with f-strings/% formatting/.format() rather than parameter binding.",
    remediation: "Use parameterized queries (e.g. cursor.execute(query, params)) instead of formatting values into the query string.",
    extensions: [".py"],
  },

  // --- PHP ---
  {
    ruleId: "code-php-eval",
    title: "Use of eval()",
    pattern: /\beval\s*\(/,
    severity: "high",
    description: "eval() executes arbitrary PHP code, a common injection vector.",
    remediation: "Avoid eval(); refactor dynamic logic into explicit functions.",
    extensions: [".php"],
  },
  {
    ruleId: "code-php-unserialize",
    title: "Untrusted deserialization via unserialize()",
    pattern: /\bunserialize\s*\(/,
    severity: "critical",
    description: "unserialize() on untrusted input can lead to PHP object injection and remote code execution.",
    remediation: "Use json_decode() for untrusted data, or restrict unserialize() with the 'allowed_classes' option.",
    extensions: [".php"],
  },
  {
    ruleId: "code-php-sql-concat",
    title: "Possible SQL injection via string concatenation",
    pattern: /\b(mysqli?_query|->query)\s*\(\s*['"].*['"]\s*\./,
    severity: "critical",
    description: "A SQL query is concatenated with variables rather than using bound parameters.",
    remediation: "Use prepared statements (PDO/mysqli with bound parameters) instead of string concatenation.",
    extensions: [".php"],
  },
  {
    ruleId: "code-php-system-exec",
    title: "Shell command execution with dynamic input",
    pattern: /\b(system|exec|shell_exec|passthru)\s*\(\s*[^)]*\$/,
    severity: "critical",
    description: "A shell command function is called with a variable, risking command injection.",
    remediation: "Avoid passing user input to shell functions; if unavoidable, use escapeshellarg()/escapeshellcmd() and strict allowlisting.",
    extensions: [".php"],
  },

  // --- Generic / cross-language ---
  {
    ruleId: "code-generic-http-url",
    title: "Hardcoded plaintext HTTP URL",
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"\s]+['"]/,
    severity: "low",
    description: "A hardcoded http:// (non-TLS) URL was found; traffic to it is unencrypted.",
    remediation: "Use https:// endpoints wherever possible, especially for anything carrying credentials or sensitive data.",
  },
  {
    ruleId: "code-generic-todo-security",
    title: "Security-related TODO/FIXME left in code",
    pattern: /\b(TODO|FIXME|XXX)\b.{0,80}(security|auth|vuln|sanitiz|escape|inject)/i,
    severity: "info",
    description: "A comment flags unresolved security work.",
    remediation: "Triage and resolve the noted security concern before shipping.",
  },
];

export function scanTextForCodePatterns(filePath: string, content: string): Finding[] {
  const ext = extname(filePath);
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);
  const applicableRules = RULES.filter((r) => !r.extensions || r.extensions.includes(ext));
  if (applicableRules.length === 0) return findings;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of applicableRules) {
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.ruleId,
          title: rule.title,
          severity: rule.severity,
          category: "code",
          description: rule.description,
          remediation: rule.remediation,
          file: filePath,
          line: i + 1,
          snippet: line.trim().slice(0, 160),
        });
      }
      rule.pattern.lastIndex = 0;
    }
  }
  return findings;
}
