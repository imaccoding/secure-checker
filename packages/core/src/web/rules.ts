import type { Finding } from "../types.js";

/**
 * Pure, isomorphic header/cookie evaluation - no Node-only APIs here so this
 * module can run unmodified in a browser extension as well as in the CLI/VSCode.
 */

export interface HeaderCheckInput {
  url: string;
  /** Lower-cased header name -> value */
  headers: Record<string, string>;
}

export function evaluateSecurityHeaders({ url, headers }: HeaderCheckInput): Finding[] {
  const findings: Finding[] = [];
  const get = (name: string) => headers[name.toLowerCase()];

  if (!get("strict-transport-security") && url.startsWith("https://")) {
    findings.push(mk("web-missing-hsts", "Missing Strict-Transport-Security header", "medium", url,
      "Without HSTS, browsers may still attempt plain HTTP connections, enabling SSL-stripping attacks.",
      "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (and consider `preload`)."));
  }

  if (!get("content-security-policy")) {
    findings.push(mk("web-missing-csp", "Missing Content-Security-Policy header", "medium", url,
      "Without a CSP, the page has no defense-in-depth against XSS and data-injection attacks.",
      "Add a Content-Security-Policy header restricting script/style/connect sources to known-good origins."));
  }

  if (!get("x-content-type-options")) {
    findings.push(mk("web-missing-xcto", "Missing X-Content-Type-Options header", "low", url,
      "Without `nosniff`, browsers may MIME-sniff responses, enabling certain content-type confusion attacks.",
      "Add `X-Content-Type-Options: nosniff` to all responses."));
  }

  const xfo = get("x-frame-options");
  const csp = get("content-security-policy") ?? "";
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    findings.push(mk("web-missing-frame-protection", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "medium", url,
      "The page can be embedded in an iframe on another site, enabling clickjacking attacks.",
      "Add `X-Frame-Options: DENY` (or SAMEORIGIN) or a CSP `frame-ancestors` directive."));
  }

  if (!get("referrer-policy")) {
    findings.push(mk("web-missing-referrer-policy", "Missing Referrer-Policy header", "info", url,
      "Without a Referrer-Policy, full URLs (potentially including sensitive query params) may leak to third parties via the Referer header.",
      "Add `Referrer-Policy: strict-origin-when-cross-origin` or stricter."));
  }

  if (!get("permissions-policy")) {
    findings.push(mk("web-missing-permissions-policy", "Missing Permissions-Policy header", "info", url,
      "Without a Permissions-Policy, powerful browser features (camera, geolocation, etc.) are not explicitly restricted.",
      "Add a Permissions-Policy header disabling features the site doesn't use."));
  }

  const server = get("server");
  if (server && /\d/.test(server)) {
    findings.push(mk("web-server-version-disclosure", "Server header discloses version information", "low", url,
      `The Server header ("${server}") reveals software/version details useful for targeting known vulnerabilities.`,
      "Configure the web server/reverse proxy to omit or generalize the Server header."));
  }

  const poweredBy = get("x-powered-by");
  if (poweredBy) {
    findings.push(mk("web-x-powered-by-disclosure", "X-Powered-By header discloses framework information", "low", url,
      `X-Powered-By ("${poweredBy}") reveals the backend framework in use.`,
      "Disable the X-Powered-By header (e.g. `app.disable('x-powered-by')` in Express)."));
  }

  const acao = get("access-control-allow-origin");
  const acac = get("access-control-allow-credentials");
  if (acao === "*" && acac === "true") {
    findings.push(mk("web-cors-wildcard-with-credentials", "CORS wildcard origin combined with credentials", "critical", url,
      "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is invalid per spec but some setups still ship it, and reflecting an arbitrary Origin with credentials enabled lets any site read authenticated responses.",
      "Return a specific allowlisted origin (never '*') whenever Access-Control-Allow-Credentials is true."));
  }

  return findings;
}

export interface CookieCheckInput {
  url: string;
  /** Raw Set-Cookie header values (one string per cookie) */
  setCookieHeaders: string[];
}

export function evaluateCookies({ url, setCookieHeaders }: CookieCheckInput): Finding[] {
  const findings: Finding[] = [];
  const isHttps = url.startsWith("https://");

  for (const raw of setCookieHeaders) {
    const name = raw.split("=")[0]?.trim() || "cookie";
    const lower = raw.toLowerCase();

    if (isHttps && !lower.includes("secure")) {
      findings.push(mk("web-cookie-missing-secure", `Cookie "${name}" missing Secure flag`, "medium", url,
        "Without Secure, the cookie can be sent over plain HTTP, exposing it to network eavesdroppers.",
        `Add the Secure attribute to the "${name}" cookie.`));
    }
    if (!lower.includes("httponly") && /sess|token|auth|id=/i.test(name)) {
      findings.push(mk("web-cookie-missing-httponly", `Cookie "${name}" missing HttpOnly flag`, "medium", url,
        "Without HttpOnly, JavaScript can read this cookie, making it a target for theft via XSS.",
        `Add the HttpOnly attribute to the "${name}" cookie.`));
    }
    if (!/samesite/i.test(raw)) {
      findings.push(mk("web-cookie-missing-samesite", `Cookie "${name}" missing SameSite attribute`, "low", url,
        "Without SameSite, the cookie may be sent on cross-site requests, increasing CSRF exposure.",
        `Add SameSite=Lax (or Strict) to the "${name}" cookie.`));
    }
  }

  return findings;
}

function mk(ruleId: string, title: string, severity: Finding["severity"], url: string, description: string, remediation: string): Finding {
  return {
    ruleId,
    title,
    severity,
    category: ruleId.startsWith("web-cookie") ? "web-cookie" : ruleId.includes("cors") ? "web-cors" : "web-header",
    description,
    remediation,
    location: url,
  };
}
