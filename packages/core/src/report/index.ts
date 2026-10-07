import type { ScanResult } from "../types.js";
import { toHtml } from "./html.js";
import { toMarkdown } from "./markdown.js";

export type ReportFormat = "html" | "markdown" | "json";

export function renderReport(result: ScanResult, format: ReportFormat): string {
  switch (format) {
    case "html":
      return toHtml(result);
    case "markdown":
      return toMarkdown(result);
    case "json":
      return JSON.stringify(result, null, 2);
  }
}

export { toHtml, toMarkdown };
