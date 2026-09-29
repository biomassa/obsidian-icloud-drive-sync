/**
 * Which paths are never synced, and the canonical form of a path key.
 *
 * Ported from obsisync's filters.py with two fixes from its review:
 *
 * - A folder pattern ("Archive/") matches everything *inside* the folder, not
 *   only the folder itself. obsisync's scans pruned the folder so they were
 *   right, but the watcher checked files one by one and fired on every edit
 *   under an ignored folder.
 * - `.obsidian/workspace*` matched `workspaces.json`, which is the Workspaces
 *   core plugin's saved layouts — user data — so it was silently never synced.
 *   Only the two volatile layout files are ignored now.
 *
 * The same predicate must reach every consumer: both scans *and* the watcher.
 * Filtering one side only makes an ignored file look deleted on that side.
 */

export const DEFAULT_IGNORE: readonly string[] = [
  // editors and OS droppings
  "*.tmp",
  "*.swp",
  "*.part",
  ".DS_Store",
  "._*",
  "~$*",
  // iCloud placeholders for files not yet downloaded on a Mac
  "*.icloud",
  // Obsidian's own local trash
  ".trash/",
  // this plugin's temporary names, locally and on iCloud
  ".icloudsync-tmp-*",
  // rewritten constantly by Obsidian; syncing them fights between devices
  ".obsidian/workspace.json",
  ".obsidian/workspace-mobile.json",
  // iCloud's own conflict copies of those two
  ".obsidian/workspace.json.conflict*",
  ".obsidian/workspace-mobile.json.conflict*",
];

/** fnmatch-style glob → RegExp. `*` and `?` match any character, including "/". */
function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      const end = glob.indexOf("]", i + 1);
      if (end < 0) re += "\\[";
      else {
        let body = glob.slice(i + 1, end);
        if (body.startsWith("!")) body = "^" + body.slice(1);
        re += `[${body.replace(/\\/g, "\\\\")}]`;
        i = end;
      }
    } else re += c.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`, "s");
}

export class IgnoreFilter {
  private readonly folderPatterns: RegExp[] = [];
  private readonly filePatterns: RegExp[] = [];
  readonly patterns: readonly string[];

  constructor(extra: readonly string[] = [], defaults: readonly string[] = DEFAULT_IGNORE) {
    this.patterns = [...defaults, ...extra.map((p) => p.trim()).filter(Boolean)];
    for (const p of this.patterns) {
      if (p.endsWith("/")) this.folderPatterns.push(globToRegExp(p.slice(0, -1)));
      else this.filePatterns.push(globToRegExp(p));
    }
  }

  /**
   * True when `key` must not sync. A file pattern matches the file name or the
   * whole path, as fnmatch did in obsisync. A folder pattern ("x/") matches a
   * folder whose path, or whose own name, fits it — so ".trash/" also covers a
   * nested ".trash" — and everything inside that folder.
   */
  ignores(key: string): boolean {
    const parts = key.split("/");
    for (let depth = 1; depth <= parts.length; depth++) {
      const prefix = parts.slice(0, depth).join("/");
      const segment = parts[depth - 1]!;
      if (this.folderPatterns.some((re) => re.test(prefix) || re.test(segment))) return true;
    }
    const name = parts[parts.length - 1]!;
    return this.filePatterns.some((re) => re.test(name) || re.test(key));
  }

  /** For scans: whether to skip descending into a folder at all. */
  ignoresFolder(folderKey: string): boolean {
    return this.ignores(folderKey);
  }
}

/** Canonical key: NFC, POSIX separators, no leading "./" or slash. */
export function toKey(path: string): string {
  return path.normalize("NFC").replace(/^\.?\/+/, "");
}

/**
 * iCloud Drive treats names case-insensitively, so "Note.md" and "note.md"
 * cannot both exist there even though Linux allows it. Returns each key that
 * collides with another, mapped to the one kept.
 *
 * Keys in `preferred` (already tracked) win: refusing the tracked copy would
 * make it look locally deleted. The planner never acts on a refused key.
 */
export function caseCollisions(keys: Iterable<string>, preferred: ReadonlySet<string> = new Set()): Map<string, string> {
  const seen = new Map<string, string>();
  const collisions = new Map<string, string>();
  const ordered = [...keys].sort((a, b) => Number(preferred.has(b)) - Number(preferred.has(a)) || (a < b ? -1 : a > b ? 1 : 0));
  for (const key of ordered) {
    const folded = key.toLowerCase();
    const first = seen.get(folded);
    if (first !== undefined) collisions.set(key, first);
    else seen.set(folded, key);
  }
  return collisions;
}
