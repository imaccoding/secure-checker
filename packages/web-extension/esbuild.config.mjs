import { build } from "esbuild";

const common = {
  bundle: true,
  format: "esm",
  target: "chrome110",
  sourcemap: true,
  outdir: "dist",
  logLevel: "info",
};

await build({
  ...common,
  entryPoints: {
    background: "src/background.ts",
    popup: "src/popup.ts",
  },
});
