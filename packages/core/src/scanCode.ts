import { readFile } from "node:fs/promises";
import { relative } from "node:path";
import { walkScannableFiles } from "./fsWalk.js";
import { scanTextForSecrets } from "./rules/secrets.js";
import { scanTextForCodePatterns } from "./rules/codePatterns.js";
import { scanConfigFile, scanProjectConfig } from "./rules/configChecks.js";
import { scanNpmDependencies, scanPythonDependencies } from "./rules/dependencies.js";
import { summarize, sortFindings, type ScanMode, type ScanResult, type Finding } from "./types.js";

export interface ScanCodeOptions {
  mode: ScanMode;
  /** Called with progress updates, useful for CLI/extension UI */
  onProgress?: (message: string) => void;
}

const QUICK_MAX_FILES = 300;
const MAX_FILE_SIZE_BYTES = 1_500_000;

export async function scanCodebase(targetPath: string, options: ScanCodeOptions): Promise<ScanResult> {
  const startedAt = new Date();
  const { mode, onProgress } = options;

  const files = await walkScannableFiles(targetPath, {
    maxFiles: mode === "quick" ? QUICK_MAX_FILES : Infinity,
  });

  onProgress?.(`Scanning ${files.length} file(s) in ${mode} mode...`);

  const findings: Finding[] = [];
  let filesScanned = 0;

  for (const file of files) {
    let content: string;
    try {
      const data = await readFile(file);
      if (data.byteLength > MAX_FILE_SIZE_BYTES) continue;
      content = data.toString("utf8");
    } catch {
      continue;
    }

    const relPath = relative(targetPath, file) || file;
    findings.push(...scanTextForSecrets(relPath, content));
    findings.push(...scanTextForCodePatterns(relPath, content));
    findings.push(...(await scanConfigFile(relPath, content)));
    filesScanned++;
  }

  findings.push(...(await scanProjectConfig(targetPath)));

  if (mode === "detailed") {
    onProgress?.("Running dependency audit (npm/pip)...");
    const [npmFindings, pipFindings] = await Promise.all([
      scanNpmDependencies(targetPath),
      scanPythonDependencies(targetPath),
    ]);
    findings.push(...npmFindings, ...pipFindings);
  }

  const finishedAt = new Date();
  const sorted = sortFindings(findings);

  return {
    target: targetPath,
    targetType: "codebase",
    mode,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    findings: sorted,
    summary: summarize(sorted),
    filesScanned,
  };
}
