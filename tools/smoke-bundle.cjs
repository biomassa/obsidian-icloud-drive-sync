// Load the built main.js the way Obsidian does (CommonJS), with a stub for the
// "obsidian" module, to catch bundling and import-time errors without Obsidian.
//   npm run build && node tools/smoke-bundle.cjs
const Module = require("module");
const { copyFileSync } = require("fs");
const { join } = require("path");
const { tmpdir } = require("os");

const original = Module._load;
const stub = new Proxy({}, { get: (_, key) => (key === "__esModule" ? false : class {}) });
Module._load = function (request, ...rest) {
  if (request === "obsidian") return stub;
  return original.call(this, request, ...rest);
};
// The package is "type": "module", so load a .cjs copy.
const copy = join(tmpdir(), `icloud-drive-sync-smoke-${process.pid}.cjs`);
copyFileSync(join(__dirname, "..", "main.js"), copy);
const plugin = require(copy);
if (typeof plugin.default !== "function") {
  console.error("main.js does not export a plugin class");
  process.exit(1);
}
console.log("main.js loads and exports the plugin class");
