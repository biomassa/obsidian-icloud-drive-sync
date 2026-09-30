/**
 * The activity log, kept across restarts in a file next to the sync state:
 * outside the vault, so it never syncs, and readable only by this user.
 *
 * One JSON object per line. The file is rewritten as a whole, atomically and
 * at most every `debounceMs`, rather than appended to: with a cap of 1000
 * entries it stays around 100 KB, and a rewrite keeps the cap exact without a
 * separate compaction step.
 */
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type { LogLevel } from "../sync/engine.ts";

export interface LogLine {
  at: number;
  level: LogLevel;
  message: string;
}

const LEVELS = new Set(["debug", "info", "warn", "error"]);

function parseLine(text: string): LogLine | null {
  try {
    const v = JSON.parse(text);
    if (typeof v?.at === "number" && LEVELS.has(v.level) && typeof v.message === "string") {
      return { at: v.at, level: v.level, message: v.message };
    }
  } catch {
    // a torn or foreign line: skip it
  }
  return null;
}

export class PersistentLog {
  /** Null keeps the log in memory only (tests). */
  readonly path: string | null;
  readonly limit: number;
  entries: LogLine[] = [];
  private readonly debounceMs: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private writing: Promise<void> = Promise.resolve();

  constructor(path: string | null, options: { limit?: number; debounceMs?: number } = {}) {
    this.path = path;
    this.limit = options.limit ?? 1000;
    this.debounceMs = options.debounceMs ?? 2000;
  }

  /** Read the stored log. Entries added before loading are kept after it. */
  async load(): Promise<void> {
    if (!this.path) return;
    let text = "";
    try {
      text = await readFile(this.path, "utf8");
    } catch {
      return; // no log yet
    }
    const stored = text.split("\n").map(parseLine).filter((l): l is LogLine => l !== null);
    this.entries = [...stored, ...this.entries].slice(-this.limit);
  }

  add(line: LogLine): void {
    this.entries.push(line);
    if (this.entries.length > this.limit) this.entries.splice(0, this.entries.length - this.limit);
    this.schedule();
  }

  private schedule(): void {
    if (!this.path || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, this.debounceMs);
  }

  /** Write now. Writes are queued, so they never interleave. */
  flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const path = this.path;
    if (!path) return Promise.resolve();
    const text = this.entries.map((l) => JSON.stringify(l)).join("\n") + (this.entries.length ? "\n" : "");
    this.writing = this.writing
      .catch(() => undefined)
      .then(async () => {
        await mkdir(dirname(path), { recursive: true, mode: 0o700 });
        await chmod(dirname(path), 0o700);
        const tmp = `${path}.${process.pid}.tmp`;
        await writeFile(tmp, text, { mode: 0o600 });
        await rename(tmp, path);
      });
    return this.writing;
  }

  /** Empty the log, in memory and on disk. */
  async clear(): Promise<void> {
    this.entries = [];
    await this.flush();
  }
}
