import type { Finding } from "../types.js";

interface SecretPattern {
  ruleId: string;
  title: string;
  pattern: RegExp;
  severity: Finding["severity"];
  description: string;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    ruleId: "secret-aws-access-key",
    title: "Hardcoded AWS Access Key ID",
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
    severity: "critical",
    description: "An AWS access key ID appears to be hardcoded in source.",
    remediation:
      "Revoke this key in IAM immediately, remove it from source and git history, and load credentials from environment variables, a secrets manager (AWS Secrets Manager/SSM), or an instance role instead.",
  },
  {
    ruleId: "secret-aws-secret-key",
    title: "Possible hardcoded AWS Secret Access Key",
    pattern: /aws(.{0,20})?(secret|private)[_-]?(access)?[_-]?key(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/i,
    severity: "critical",
    description: "A value matching the shape of an AWS secret access key appears hardcoded.",
    remediation: "Rotate the key in IAM, remove it from source, and use a secrets manager or environment variables.",
  },
  {
    ruleId: "secret-private-key-block",
    title: "Embedded private key",
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/,
    severity: "critical",
    description: "A PEM-formatted private key is embedded directly in a file.",
    remediation:
      "Remove the private key from the repository, rotate/reissue it, and load keys from a secrets manager, KMS, or a file outside version control with restricted permissions.",
  },
  {
    ruleId: "secret-github-token",
    title: "Hardcoded GitHub token",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/,
    severity: "critical",
    description: "A GitHub personal access/app token appears hardcoded.",
    remediation: "Revoke the token in GitHub settings, remove it from source and history, and use environment secrets (e.g. GitHub Actions secrets).",
  },
  {
    ruleId: "secret-slack-token",
    title: "Hardcoded Slack token",
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    severity: "high",
    description: "A Slack API token appears hardcoded.",
    remediation: "Revoke the token in Slack app settings and load it from environment variables or a secrets manager.",
  },
  {
    ruleId: "secret-google-api-key",
    title: "Hardcoded Google API key",
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    severity: "high",
    description: "A Google API key appears hardcoded.",
    remediation: "Restrict/rotate the key in Google Cloud Console and load it from environment configuration, not source.",
  },
  {
    ruleId: "secret-jwt",
    title: "Hardcoded JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    severity: "medium",
    description: "A JSON Web Token appears hardcoded, which may leak session/identity data or allow replay.",
    remediation: "Remove hardcoded tokens; issue tokens dynamically and keep test fixtures out of production source.",
  },
  {
    ruleId: "secret-generic-password",
    title: "Hardcoded password/credential",
    pattern: /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"\s]{6,}['"]/i,
    severity: "high",
    description: "A string assignment looks like a hardcoded credential or API key.",
    remediation: "Move credentials to environment variables or a secrets manager, and add the file to .gitignore if it holds real secrets.",
  },
  {
    ruleId: "secret-db-connection-string",
    title: "Database connection string with embedded credentials",
    pattern: /(postgres|postgresql|mysql|mongodb(\+srv)?|redis):\/\/[^:\s'"]+:[^@\s'"]+@/i,
    severity: "high",
    description: "A database connection string includes a plaintext username and password.",
    remediation: "Use environment variables for credentials and inject them at runtime instead of hardcoding connection URIs.",
  },
  {
    ruleId: "secret-slack-webhook",
    title: "Hardcoded Slack webhook URL",
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9/]{20,}/,
    severity: "medium",
    description: "A Slack incoming webhook URL is hardcoded; anyone with it can post to the channel.",
    remediation: "Store the webhook URL in environment configuration/secrets rather than source control.",
  },
  {
    ruleId: "secret-stripe-key",
    title: "Hardcoded Stripe API key",
    pattern: /\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b/,
    severity: "critical",
    description: "A Stripe secret/restricted API key appears hardcoded.",
    remediation: "Roll the key in the Stripe dashboard immediately and load it from environment variables or a secrets manager.",
  },
];

export function scanTextForSecrets(filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of SECRET_PATTERNS) {
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.ruleId,
          title: rule.title,
          severity: rule.severity,
          category: "secret",
          description: rule.description,
          remediation: rule.remediation,
          file: filePath,
          line: i + 1,
          snippet: redact(line.trim()),
        });
      }
      rule.pattern.lastIndex = 0;
    }
  }
  return findings;
}

function redact(line: string): string {
  if (line.length <= 120) return maskSecretLike(line);
  return maskSecretLike(line.slice(0, 117)) + "...";
}

function maskSecretLike(line: string): string {
  // Keep the structure visible but mask long alnum tokens so reports don't leak the actual secret.
  return line.replace(/[A-Za-z0-9/+_-]{12,}/g, (m) => m.slice(0, 4) + "..." + m.slice(-2));
}
