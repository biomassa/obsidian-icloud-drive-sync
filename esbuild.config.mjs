import esbuild from "esbuild";
import { builtinModules } from "node:module";

const production = process.argv[2] === "production";

// Obsidian supplies `obsidian` and `electron` at runtime, and the plugin runs
// with Node integration, so Node builtins are required rather than bundled.
const external = [
  "obsidian",
  "electron",
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
];

const ctx = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  external,
  format: "cjs",
  // Obsidian's Electron ships an older Node than a development machine may
  // have. ES2022 is well inside what every supported Obsidian runs.
  target: "es2022",
  platform: "node",
  logLevel: "info",
  sourcemap: production ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
});

if (production) {
  await ctx.rebuild();
  await ctx.dispose();
} else {
  await ctx.watch();
}
