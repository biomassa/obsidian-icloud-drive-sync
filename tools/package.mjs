// Build the release files for a manual install:
//
//   dist/icloud-drive-sync/{main.js,manifest.json,styles.css}
//   dist/icloud-drive-sync-<version>.zip   (unzips into .obsidian/plugins/)
//
// Refuses when the versions in manifest.json, package.json and versions.json
// disagree, so a release can never ship a manifest that says something else.
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

const read = (f) => JSON.parse(readFileSync(f, "utf8"));
const manifest = read("manifest.json");
const pkg = read("package.json");
const versions = read("versions.json");
const version = manifest.version;

const problems = [];
if (pkg.version !== version) problems.push(`package.json says ${pkg.version}, manifest.json says ${version}`);
if (versions[version] !== manifest.minAppVersion) {
  problems.push(`versions.json must map ${version} to minAppVersion ${manifest.minAppVersion}`);
}
const tag = process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : undefined;
if (tag !== undefined && tag !== version) problems.push(`the tag ${tag} must equal the manifest version ${version}`);
if (!existsSync("main.js")) problems.push("main.js is missing; run npm run build first");
if (problems.length) {
  console.error(`Not packaging:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}

const folder = join("dist", manifest.id);
rmSync("dist", { recursive: true, force: true });
mkdirSync(folder, { recursive: true });
for (const file of ["main.js", "manifest.json", "styles.css"]) copyFileSync(file, join(folder, file));
const zip = `${manifest.id}-${version}.zip`;
execFileSync("zip", ["-qr", zip, manifest.id], { cwd: "dist" });
console.log(`dist/${manifest.id}/ and dist/${zip} ready for ${manifest.name} ${version}`);
