import { connect, type TLSSocket } from "node:tls";
import type { Finding } from "../types.js";

export function checkTls(hostname: string, port = 443): Promise<Finding[]> {
  return new Promise((resolve) => {
    const findings: Finding[] = [];
    const url = `https://${hostname}`;
    const socket: TLSSocket = connect(
      { host: hostname, port, servername: hostname, timeout: 8000 },
      () => {
        const cert = socket.getCertificate();
        const protocol = socket.getProtocol();

        if (protocol && (protocol === "TLSv1" || protocol === "TLSv1.1")) {
          findings.push({
            ruleId: "web-tls-outdated-protocol",
            title: `Outdated TLS protocol negotiated: ${protocol}`,
            severity: "high",
            category: "web-tls",
            description: `The server negotiated ${protocol}, which is deprecated and has known weaknesses.`,
            remediation: "Disable TLS 1.0/1.1 on the server and require TLS 1.2 or newer.",
            location: url,
          });
        }

        if (cert && "valid_to" in cert) {
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.floor((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          if (daysLeft < 0) {
            findings.push({
              ruleId: "web-tls-cert-expired",
              title: "TLS certificate has expired",
              severity: "critical",
              category: "web-tls",
              description: `The certificate expired on ${cert.valid_to}.`,
              remediation: "Renew the TLS certificate immediately.",
              location: url,
            });
          } else if (daysLeft < 14) {
            findings.push({
              ruleId: "web-tls-cert-expiring-soon",
              title: `TLS certificate expires in ${daysLeft} day(s)`,
              severity: "medium",
              category: "web-tls",
              description: `The certificate expires on ${cert.valid_to}.`,
              remediation: "Renew the TLS certificate before it expires to avoid an outage/browser warnings.",
              location: url,
            });
          }
        }

        socket.end();
        resolve(findings);
      }
    );

    socket.on("error", () => resolve(findings));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(findings);
    });
  });
}
