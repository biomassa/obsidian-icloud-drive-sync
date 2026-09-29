# iCloud Drive Sync — plan

An Obsidian plugin that does what obsisync does — two-way sync of a vault with iCloud Drive on
Linux and Windows — with the bugs found in obsisync's review fixed rather than ported. No rclone,
no helper daemon: the iCloud client is a TypeScript port of obsisync's `icloudlite`.

## Decisions

| Question | Decision | Why |
|---|---|---|
| iCloud client | Port `icloudlite` to TypeScript | `icloudjs` cannot upload and has no trusted-device 2FA |
| 2FA | Trusted-device prompt *and* SMS from the start | Apple routes most accounts to the device prompt |
| HTTP | Node `https` + own cookie jar | Chromium `fetch` applies CORS, hides Set-Cookie, fixes Origin |
| Push websocket | Hand-rolled over `tls` | Chromium's WebSocket cannot send Apple's Origin/User-Agent |
| Platform | `isDesktopOnly: true`, `minAppVersion` 1.11.4 | Node APIs; `app.secretStorage` arrived in 1.11.4 |
| Credentials | `app.secretStorage` only — never `data.json` | the vault is what gets synced; `data.json` is in the vault |
| Tests | `node --test` on `.ts` directly | no test framework, no transpile step |

### Credentials never reach iCloud

Obsidian's `secretStorage` (verified in the 1.13 app bundle) encrypts with Electron `safeStorage`
— libsecret/KWallet on Linux, DPAPI on Windows — and writes to Obsidian's browser storage under
`~/.config/obsidian`, outside every vault. Password, session token, trust token and cookies all go
there. `data.json` holds an allow-list of non-secret settings, enforced by a test.

If `safeStorage` reports the `basic_text` backend (Linux with no keyring), Obsidian would store
secrets unencrypted — still outside the vault, but the plugin should refuse and say why, as
obsisync's `_assert_secure_keyring()` does.

## Phases

0. **Scaffold** — done.
1. **Auth + Drive spike from plain Node** (`spike/cli.ts`), against the real account:
   - [x] SRP parity with icloudlite (offline vectors)
   - [x] SPAKE2 prover and push-protocol parity (offline vectors)
   - [x] sign-in state machine and bridge flow against simulated Apple
   - [x] live sign-in with trusted-device 2FA; trust token survives a fresh process
   - [x] walk the vault: 895 files / 98 folders; all 833 obsisync paths found, the 62 extra
         all explained by obsisync's ignore patterns; every file has an etag; `numberOfItems`
         matched on every folder. 6 s with 8 concurrent listings (209 s sequentially)
   - [x] downloads byte-identical (8 KB note, 2.2 MB image)
   - [x] upload, same-size replace (one `note.md` afterwards, new etag), empty file, nested
         folder, trash — all in a throwaway root folder

   Spike findings to carry into phase 2:
   - **Requests must match python-requests byte for byte.** The first live sign-in was
     rejected (-20101) with the right password and a proof identical to Python's; after
     matching JSON separators, header order, `Accept-Encoding` and `Connection`, the next one
     was accepted. Which difference mattered is unknown — keep all of them.
   - **Replace costs a Recently Deleted entry per edit.** Upload-then-trash is safe, but every
     synced edit leaves the previous version in Recently Deleted. Investigate updating a
     document in place (`update/documents` against the existing document) before phase 3.
   - A replace takes ~10 s (upload, list, trash, rename); uploads ~3 s, listings ~1 s.

   iCloud semantics, probed live in throwaway folders (spike `semantics`, `semantics2`,
   `semantics3`, 2026-09-29):
   - `update/documents` returns the new document (id, etag, name, parent) — no listing needed.
   - Rename and move keep `docwsid`/`drivewsid`; both change the etag. `renameItems` takes the
     full name and splits the extension itself.
   - **A trash with a stale etag answers 200 and does nothing.** The response item's `parentId`
     is `TRASH_ROOT` only when it really moved; check it every time.
   - `allow_conflict: false` on a taken name fails ("Uniqueness constraint violation"): a real
     create-if-absent.
   - Names are case-sensitive through the web API (`Case.md` and `case.md` coexist), but Apple
     devices usually are not, so local case collisions are still refused.
   - **In-place update works:** `add_file` with the existing `document_id` replaces the content
     and keeps the id, with no temp name and no Recently Deleted entry. It is unconditional —
     `etag`, `document_etag` and `if_match` are all ignored — so the executor re-reads the etag
     just before updating and skips if it moved (≈1 s unguarded window, last-writer-wins).
2. **Sync engine in pure TypeScript** — done (`src/sync/`, no Obsidian imports):
   - [x] pure planner (`planner.ts`), guards on the whole plan, then an executor (`engine.ts`)
         that re-checks each local file right before acting and records only what it actually
         read or wrote; a path is marked synced only after its own transfer succeeded
   - [x] whole-file SHA-256; the cheap pre-check compares size, mtime, ctime and inode, with a
         racy-clean window; no same-size shortcut
   - [x] replace = in-place update guarded by an etag re-read; trash verified from the response;
         new files create-if-absent; Apple's zone-lock rejections retried
   - [x] deletion guard in both directions (> 3 parked, persisted, false alarms clear, a pending
         question absorbs later deletions); any unreadable folder or truncated listing aborts
   - [x] conflicts keep both versions as files, on both sides
   - [x] NFC keys; NFC/case collisions and symlinks refused *and protected*
   - [x] renames both ways: remote by document id (with a content check, since a move changes the
         etag), local by unique content hash
   - [x] an expired session stops the cycle at once; re-auth is the plugin shell's job
   - [x] tests: decision table incl. obsisync's regressions, executor races, real-filesystem
         adapter, and a randomized two-sided no-loss test (20,000 seeds; found 4 bugs)
   - [x] live end-to-end (`spike/cli.ts e2e`): upload, same-size edit, >4 KB append, other-device
         edit, renames both ways, conflict, deletions both ways, quiet cycles — trees identical
         after every step

   Left for later: pruning folders emptied by deletions (they stay behind after renames).

   **Read-only first-run plan against the real vault** (`spike/cli.ts plan-real`, nothing
   executed): 834 local / 870 iCloud files. 831 same-size files would be compared by content
   (314.8 MB downloaded once, mostly `.obsidian` plugin data: a 60 MB Copilot index, icon zips
   up to 31 MB); 3 conflicts, all plugin code whose versions differ between devices
   (`obsidian-tasks-plugin/main.js`, two `styles.css`); 36 downloads that were all iCloud's own
   `workspace N.json` / `workspace(1).json` duplicates — now ignored by default. Hashing 316 MB
   locally took 0.6 s; peak RSS 195 MB. The iCloud walk took 6 s once and 37 s another time.

3. **Obsidian shell** — built; first manual test pending:
   - [x] scheduler (`src/sync/scheduler.ts`): poll, debounced local changes against a cached
         iCloud scan, deferral, echo suppression — tested on a virtual clock
   - [x] controller (`src/plugin/controller.ts`): sign-in only on a click, never retried;
         resume from stored tokens first; one-time notices — tested against FakeApple
   - [x] settings allow-list (data.json can never hold a secret), session in `secretStorage`,
         refusal on plaintext secret storage or an obsisync-managed vault, plugin code excluded
   - [x] UI: sign-in and 2FA dialogs, status view with deletion / conflict / ignored decisions,
         settings tab with vault discovery, status bar, commands, ribbon icon
   - [ ] manual test in `~/obsi-plugin-test` ↔ iCloud `icloudsync-plugin-test`

   Constraints found so far:
   - Reuse a recent remote scan for watcher-triggered cycles; walk the whole tree only on the
     poll timer (a walk is 98 listings and took up to 37 s). A stale scan cannot cause false
     deletions, and every write re-checks the etag first.
   - Exclude the plugin's own folder (`.obsidian/plugins/icloud-drive-sync/`): its code and
     `data.json` are per device and per version.
   - Password sign-in only on an explicit click; never on a timer, never retried after a
     rejection. It has only ever succeeded from standalone Node — Electron's TLS stack is
     untested against Apple — so seed `secretStorage` from the trusted spike session for
     development and only resume.
   - The first run's content comparison needs a progress display (hundreds of MB).
   - Writing a download into a note open in the editor needs care; hashing large files must
     yield to the UI.
   - Residual race: updates and moves re-check the etag ~1 s before writing, but Apple applies
     them unconditionally, so an edit on another device inside that second is overwritten.
3. **Obsidian shell** — settings tab, sign-in and 2FA modals, status bar, conflict view,
   adapter-level scanning of `.obsidian/`, per-path echo suppression for our own writes.

## Safety rules for development

- Throwaway vault and throwaway iCloud folder until the phase-2 tests pass.
- Never run the plugin and obsisync against the same vault.
- The spike only reads the vault; `write-test` works in `icloudsync-spike-test/` at the Drive
  root and trashes it afterwards.

## Live sign-in safety

Two failed sign-ins locked the Apple ID on 2026-09-29. Every live sign-in now recomputes the
SRP proof with obsisync's Python on Apple's real challenge and aborts, with nothing sent,
unless both agree (`verifySrpProof`, `spike/cli.ts --dry-run`). One attempt at a time, run by
the user in their own terminal.

## Known divergences from icloudlite

- **SRP salt with a leading zero byte.** obsisync's pysrp OpenSSL backend drops it; this port
  hashes the raw bytes (RFC 5054). Affects ~1 account in 256; see `src/icloud/srp.ts`.
