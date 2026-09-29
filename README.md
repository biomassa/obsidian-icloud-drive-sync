# iCloud Drive Sync for Obsidian

Two-way sync between an Obsidian vault on **Linux or Windows** and the same vault in
**iCloud Drive**, so it stays in step with Obsidian on your iPhone, iPad and Mac.

On Apple devices iCloud Drive syncs vaults by itself. Linux has no iCloud client at all, and this
plugin is the missing piece: it talks to iCloud Drive directly, from inside Obsidian.

> **Status: early (0.1.0).** In daily use on Linux. **Windows is not yet tested.** Keep a backup of
> your vault before the first sync.

## What it does

- Syncs both ways: edits, new files, renames and deletions, in both directions, including your
  `.obsidian` settings.
- **Never loses a version.** When a note changed on both sides, both versions are kept as files: the
  newer under the original name, the other as `name (conflict 2026-09-29 1430).md`.
- **Never deletes permanently.** A file deleted on one side is moved to the other side's trash: the
  vault's trash here, *Recently Deleted* on iCloud (recoverable there for 30 days).
- **Asks before bulk deletions.** More than 3 deletions in one sync (adjustable) wait for your
  confirmation, in either direction. The question survives restarts, and clears itself if the files
  turn out to be present after all.
- **Recognises renames** on both sides, so renaming a folder on your iPhone renames it here instead of
  deleting and re-downloading everything in it.
- Syncs a few seconds after you stop typing, and checks iCloud for changes from other devices every
  2 minutes (adjustable; iCloud cannot notify of changes).

## Requirements

- Obsidian **1.11.4 or newer**, on **Linux or Windows** desktop. (It refuses to run on a Mac, where
  iCloud Drive already syncs the vault, and it cannot run on mobile.)
- An Apple ID with **iCloud Drive** turned on.
- **Advanced Data Protection must be off**, and **Access iCloud Data on the Web** must be on
  (iPhone: Settings → your name → iCloud). The plugin uses iCloud's web interface, the same one
  icloud.com uses, which Advanced Data Protection disables.
- An existing vault in iCloud Drive, for example one created by Obsidian on your iPhone.
- **Linux only:** a keyring (gnome-keyring, KWallet or KeePassXC) so Obsidian can encrypt the stored
  session. See [Troubleshooting](#troubleshooting) if you use niri, Hyprland, Sway or another
  desktop that is not GNOME or KDE.

## Install (manual)

1. Download `icloud-drive-sync-<version>.zip` from the
   [latest release](../../releases/latest).
2. Unzip it into your vault's plugin folder, so that you end up with:
   ```
   <your vault>/.obsidian/plugins/icloud-drive-sync/main.js
   <your vault>/.obsidian/plugins/icloud-drive-sync/manifest.json
   <your vault>/.obsidian/plugins/icloud-drive-sync/styles.css
   ```
   The `.obsidian` folder is hidden; show hidden files, or create the folders by hand. You can also
   download the three files individually from the release and put them in that folder yourself.
3. In Obsidian: **Settings → Community plugins**. If asked, turn off Restricted mode. Click the
   refresh icon next to *Installed plugins*, then enable **iCloud Drive Sync**.

To update, replace the three files with those from a newer release and restart Obsidian (or turn the
plugin off and on).

## Set up

1. **Settings → iCloud Drive Sync → Apple ID**: enter your Apple ID's email address.
2. **Sign in…**: enter your password. Apple then shows a prompt on your iPhone or Mac; allow it and type
   the code it shows (or choose *Text me a code instead*).
3. **Find vaults** lists the Obsidian vaults in your iCloud Drive. Pick yours from the list, and syncing
   starts.

**If this vault is new and empty**, the first sync simply downloads the vault from iCloud. Obsidian's
freshly created default settings are moved to the vault's trash, so your real settings from iCloud
take their place.

**If this vault already has notes** (say you copied the vault over, or used another sync tool before),
the first sync compares every file present on both sides by content. It has to download each of them
once to do so, which can take a while for a large vault; the status bar shows progress. Files that
match are simply recorded as in sync. Files that differ are kept twice, never overwritten.

Do not run another sync tool on the same vault at the same time. Two tools each see the other's
writes as edits and fight. If you used obsisync on this vault, stop it first; the plugin refuses to
start while obsisync is configured for the same folder.

## Using it

- The status bar shows **iCloud ✓** when in sync, a counter while syncing, **⚠** when a decision is
  waiting (deletions, many conflicts) and **✗** after an error. Click it for details, the pending
  decisions and a log of recent activity.
- Commands (Ctrl/Cmd+P): *Sync now*, *Show status*, *Pause syncing*, *Resume syncing*.
- Pausing stops a sync in progress after the current file; nothing is left half-done.

### What is not synced

- `.obsidian/workspace.json` and `workspace-mobile.json` (window layouts, rewritten constantly by
  Obsidian) and iCloud's own duplicates of them.
- Plugins' **code** (`main.js`, `styles.css`, `manifest.json` under `.obsidian/plugins/`), because desktop
  and mobile often run different versions. Their **settings** do sync. *Sync plugin code* turns this
  on.
- This plugin's own folder, including its settings.
- The vault's trash, editor temporary files, and macOS/iCloud placeholder files.
- Anything matching the patterns you add under *Also ignore*: `Archive/` ignores a folder and
  everything in it, `*.bak` matches file names.

## Privacy and security

- **Your password is used once**, when you click *Sign in*, and is never stored. Signing in is never
  retried automatically, because repeated failures can lock an Apple ID.
- The resulting **session** (Apple's session and trust tokens, and cookies) is kept in Obsidian's
  **secret storage**, which is encrypted by your system's credential store (the keyring on Linux,
  DPAPI on Windows) and lives in Obsidian's own profile, **outside the vault** — so
  it never syncs anywhere. The plugin refuses to store it if secret storage is not encrypted.
- The plugin's settings file (inside the vault) holds only your Apple ID's address and preferences;
  a test ensures nothing secret can be written there.
- What was synced when is recorded per device, outside the vault
  (`~/.local/share/icloud-drive-sync/` on Linux, `%LOCALAPPDATA%\icloud-drive-sync\` on Windows).
- The plugin talks only to Apple's iCloud servers. No telemetry, no other servers.

When your session expires (typically after weeks or months), the plugin first tries to renew it from
the stored tokens; if Apple asks for a password again, it pauses and tells you to sign in.

## Limitations

- **Apple's unofficial web interface.** iCloud Drive has no public API. This plugin speaks the same
  protocol as icloud.com (the one the pyicloud project implements), so
  Apple can change or break it at any time. This project is not affiliated with Apple.
- **Polling.** Changes from other devices arrive at the next check (every 2 minutes by default).
- **A small last-writer-wins window.** Before replacing a file on iCloud, the plugin checks that nobody
  changed it since it last looked, about a second earlier. Apple provides no way to make the
  replacement itself conditional, so an edit on another device inside that second can be overwritten.
- Folders emptied by deletions or renames are left behind.
- Large first syncs of an existing vault download every shared file once to compare them.

## Troubleshooting

**"Obsidian is storing secrets unencrypted"** (Linux). Electron, which Obsidian is built on, only
detects the keyring under GNOME and KDE. On other desktops, tell it which one to use: add one line to
`~/.config/obsidian/user-flags.conf` and restart Obsidian:

```
--password-store=gnome-libsecret
```

(for gnome-keyring or KeePassXC), or `--password-store=kwallet6` for KWallet. If Obsidian is installed as a
Flatpak or AppImage, pass the same flag on its command line instead.

**Sign-in is rejected.** Check the password on icloud.com in a private window first. Don't try
repeatedly: Apple locks an Apple ID after a few failures (unlock at
[iforgot.apple.com](https://iforgot.apple.com)).

**"iCloud Drive web access" / service not activated.** Sign in at icloud.com once, and check that
Advanced Data Protection is off and web access is on.

**Every connection stalls.** Some networks advertise IPv6 without routing it. Turn on *Use IPv4 only*.

## Build from source

```
npm ci
npm test          # 109 tests, run directly as TypeScript (Node 23.6 or newer)
npm run build     # main.js
npm run package   # dist/icloud-drive-sync-<version>.zip
```

`PLAN.md` records the design decisions, and what was verified against iCloud and how.

## License

MIT, see [LICENSE](LICENSE). The iCloud client (`src/icloud/`) is a TypeScript port of code derived
from pyicloud, used under its MIT license, reproduced in [LICENSE.pyicloud](LICENSE.pyicloud).
