import { readdir, stat } from "node:fs/promises";
import { join, extname, basename } from "node:path";

const DEFAULT_IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "out",
  "build",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
  ".secure-checker",
  "coverage",
  ".cache",
]);

const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".py",
  ".php",
  ".rb",
  ".java",
  ".go",
  ".cs",
  ".yml",
  ".yaml",
  ".json",
  ".env",
  ".toml",
  ".ini",
  ".sh",
]);

const SCANNABLE_BASENAMES = new Set(["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".env"]);

export interface WalkOptions {
  /** Maximum number of files to return; quick scans cap this to stay fast */
  maxFiles?: number;
  /** Maximum file size in bytes to read; larger files are skipped */
  maxFileSizeBytes?: number;
}

export async function walkScannableFiles(root: string, options: WalkOptions = {}): Promise<string[]> {
  const maxFiles = options.maxFiles ?? Infinity;
  const results: string[] = [];

  async function visit(dir: string): Promise<void> {
    if (results.length >= maxFiles) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name) || entry.name.startsWith(".") && entry.name !== ".env") {
          continue;
        }
        await visit(full);
      } else if (entry.isFile()) {
        const ext = extname(entry.name);
        const name = basename(entry.name);
        if (SCANNABLE_EXTENSIONS.has(ext) || SCANNABLE_BASENAMES.has(name)) {
          results.push(full);
        }
      }
    }
  }

  const rootStat = await stat(root);
  if (rootStat.isFile()) {
    return [root];
  }
  await visit(root);
  return results;
}
