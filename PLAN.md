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
2. **Sync engine in pure TypeScript** (no Obsidian imports; injected fs and remote):
   - plan (base state + local scan + remote scan → actions), check guards on the whole plan,
     then execute; a file is recorded synced only after its transfer succeeds
   - full-content hash with a size+mtime pre-check; no same-size shortcut
   - replace = upload first, trash second (never permanent delete)
   - bulk-deletion guard in **both** directions; abort on any unreadable local folder
   - conflicts always keep both versions as files
   - NFC-normalized keys; rename detection from vault events
   - re-authenticate only on 421/450, never every cycle; on 2FA, pause and notify
   - port obsisync's `test_regressions.py` as a decision table, files larger than 4 KB included
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
