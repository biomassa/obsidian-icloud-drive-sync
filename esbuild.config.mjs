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

// Obsidian gives plugins its own require(). Bare builtin names ("fs") are the
// form every desktop plugin uses; the "node:" prefix is rewritten to match.
const bareNodeBuiltins = {
  name: "bare-node-builtins",
  setup(build) {
    build.onResolve({ filter: /^node:/ }, (args) => ({ path: args.path.slice(5), external: true }));
  },
};

const ctx = await esbuild.context({
  plugins: [bareNodeBuiltins],
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
