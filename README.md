> [!CAUTION]
> **WARNING 1 OF 3: MAKE A BACKUP OF YOUR VAULT BEFORE YOU INSTALL THIS PLUGIN.**
> This plugin writes, renames and deletes files in your vault and in your iCloud Drive.
> An error in this plugin, in iCloud or on your computer can destroy your notes.
> Do not install this plugin until you have a complete backup of your vault.

> [!CAUTION]
> **WARNING 2 OF 3: MAKE A BACKUP BEFORE THE FIRST SYNC, AND MAKE BACKUPS AGAIN AT REGULAR INTERVALS.**
> The first sync changes the two copies of your vault. Later syncs change them again.
> A sync tool is not a backup. If the plugin deletes or damages a file, it can send the same
> deletion or damage to all your devices.
> Keep backups that the plugin cannot change: on a different disk, not in the vault and not in iCloud Drive.

> [!CAUTION]
> **WARNING 3 OF 3: MAKE SURE THAT YOUR BACKUP OPERATES BEFORE YOU TRUST IT.**
> Restore one file from your backup and open it. A backup that you did not test can be empty,
> old or broken. If you cannot restore your notes, you do not have a backup.
> If you do not have a tested backup, do not use this plugin.

# iCloud Drive Sync for Obsidian

This plugin syncs an Obsidian vault on Linux or Windows with the same vault in iCloud Drive.
Obsidian on your iPhone, iPad or Mac then shows the same notes.

Apple devices sync iCloud Drive vaults without a plugin. Linux has no iCloud client. This plugin
connects to iCloud Drive from Obsidian.

**Status:** early version. For the current version, refer to the [releases](../../releases). It is in daily use on Linux. It is not tested on Windows. Make a backup
of your vault before the first sync.

## Functions

- The plugin syncs in two directions. It syncs edits, new files, renames and deletions. It also syncs
  the `.obsidian` settings folder.
- If a file changes on both sides, the plugin keeps the two versions. The newer version keeps the
  original name. The other version gets a name such as `note (conflict 2026-09-29 1430).md`.
- The plugin does not delete files permanently. If you delete a file on one side, the plugin moves
  the other copy to a trash:
  - On this computer, it moves the file to the trash of the vault.
  - On iCloud, it moves the file to Recently Deleted. You can restore it from there for 30 days.
- If more than 3 files are deleted in one sync, the plugin asks you before it deletes them. You can
  change this number. The question stays after a restart. If the files come back, the question
  closes.
- The plugin finds renames on the two sides. If you rename a folder on your iPhone, the plugin
  renames the folder here. It does not delete and download the files again.
- The plugin syncs local changes 3 seconds after you stop typing. It checks iCloud for changes from
  other devices every 2 minutes. You can change this interval. iCloud does not send notifications
  of changes.

## Requirements

- Obsidian 1.11.4 or newer, on a Linux or Windows computer.
  - The plugin does not operate on a Mac, because iCloud Drive syncs the vault there.
  - The plugin does not operate on mobile devices.
- An Apple ID with iCloud Drive on.
- Advanced Data Protection must be off.
- Access iCloud Data on the Web must be on. On an iPhone, go to Settings > your name > iCloud.
- A vault in iCloud Drive. For example, a vault that Obsidian on your iPhone made.
- On Linux: a keyring, for example gnome-keyring, KWallet or KeePassXC. Obsidian uses it to encrypt
  the session. On desktops other than GNOME and KDE, read [Troubleshooting](#troubleshooting).

The plugin uses the iCloud web interface. This is the interface that icloud.com uses. Advanced Data
Protection disables this interface.

## Install

1. Download `icloud-drive-sync-<version>.zip` from the [latest release](../../releases/latest).
2. Extract the zip file into the plugin folder of your vault. The result must be:
   ```
   <vault>/.obsidian/plugins/icloud-drive-sync/main.js
   <vault>/.obsidian/plugins/icloud-drive-sync/manifest.json
   <vault>/.obsidian/plugins/icloud-drive-sync/styles.css
   ```
   The `.obsidian` folder is hidden. Set your file manager to show hidden files.
3. In Obsidian, open Settings > Community plugins.
4. If Obsidian shows Restricted mode, turn it off.
5. Select the refresh icon next to Installed plugins.
6. Turn on iCloud Drive Sync.

You can also download the three files from the release and put them in the folder yourself.

To update the plugin:

1. Replace the three files with the files from the new release.
2. Restart Obsidian. Or turn the plugin off and on again.

## Set up

1. Open Settings > iCloud Drive Sync.
2. In Apple ID, type the email address of your Apple ID.
3. Select Sign in.
4. Type your password.
5. Apple shows a prompt on your iPhone or Mac. Allow it.
6. Type the code that the prompt shows. To get a code by SMS, select Text me a code instead.
7. Select Find vaults.
8. Select your vault in the list. The first sync starts.

### First sync

The first sync operates in one of two ways:

- **The local vault is new and empty.** The plugin downloads the vault from iCloud. Obsidian makes
  default settings files for a new vault. The plugin moves these files to the trash of the vault and
  puts your settings from iCloud in their place.
- **The local vault already has notes.** The plugin compares each file that is on the two sides. To
  compare a file, it downloads the file one time. For a large vault, this takes some minutes. The
  status bar shows the progress. The plugin records equal files as synced. If two files are
  different, the plugin keeps the two versions. It does not overwrite a file.

Do not use a different sync tool on the same vault at the same time. Two tools see the changes of
the other tool as edits, and each tool changes the files again. If you used obsisync on this vault,
stop obsisync first. The plugin does not start while obsisync is set up for the same folder.

## Use

- The status bar shows the sync status:
  - **iCloud ✓**: the vault is in sync.
  - **A counter**: a sync is in progress.
  - **⚠**: a decision is necessary, for example about deletions or many conflicts.
  - **✗**: an error occurred.
- Select the status bar item to see the details, the decisions and a log of recent activity.
- To use a command, push Ctrl+P (Cmd+P on a Mac keyboard). The commands are Sync now, Show status,
  Pause syncing and Resume syncing.
- Pause stops the sync after the current file. The next sync does the remaining files.

### Files that do not sync

- `.obsidian/workspace.json` and `.obsidian/workspace-mobile.json`, and the copies of these files that
  iCloud makes. These files contain the window layout. Obsidian writes them frequently.
- The code of plugins: `main.js`, `styles.css` and `manifest.json` in `.obsidian/plugins/`. Desktop
  and mobile devices often use different versions of a plugin. The settings of plugins sync. To sync
  the code too, turn on Sync plugin code.
- The folder of this plugin, and its settings.
- The trash of the vault, temporary files of editors, and placeholder files of macOS and iCloud.
- The files that match the patterns in Also ignore. `Archive/` ignores a folder and all its contents.
  `*.bak` matches file names.

## Security

- The plugin uses your password one time, when you select Sign in. It does not keep your password.
- The plugin does not try to sign in again after a failure. A number of failed sign-ins can lock an
  Apple ID.
- The plugin keeps the session in the secret storage of Obsidian. The session contains the session
  token, the trust token and the cookies from Apple.
  - Your system encrypts the secret storage: the keyring on Linux, DPAPI on Windows.
  - The secret storage is in the profile folder of Obsidian. It is not in the vault, so it does not
    sync.
  - If the secret storage is not encrypted, the plugin does not keep the session.
- The settings file of the plugin is in the vault. It contains only your Apple ID email address and
  your settings. A test makes sure that it cannot contain secret data.
- The plugin records the sync state of each device outside the vault:
  - Linux: `~/.local/share/icloud-drive-sync/`
  - Windows: `%LOCALAPPDATA%\icloud-drive-sync\`
- The plugin connects only to the iCloud servers of Apple. It does not send telemetry.

A session usually expires after some weeks or months. The plugin then tries to renew the session with
the stored tokens. If Apple asks for the password, the plugin stops the sync and asks you to sign in.

## Limitations

- **Unofficial interface.** iCloud Drive has no public API. The plugin uses the protocol of icloud.com,
  which the pyicloud project also uses. Apple can change this protocol at any time. This project has
  no connection with Apple.
- **Interval.** Changes from other devices arrive at the next check. The default interval is 2
  minutes.
- **Short period without a lock.** Before the plugin replaces a file on iCloud, it makes sure that no
  other device changed the file. It does this approximately 1 second before the replacement. Apple
  has no function to make the replacement conditional. Thus an edit on a different device in that
  second can be lost.
- The plugin does not remove folders that become empty after deletions or renames.
- The first sync of a vault that already has notes downloads each shared file one time.

## Troubleshooting

**Obsidian stores secrets without encryption (Linux).** Obsidian uses Electron. Electron finds the
keyring only on GNOME and KDE. On other desktops, do these steps:

1. Open or make the file `~/.config/obsidian/user-flags.conf`.
2. Add this line for gnome-keyring or KeePassXC:
   ```
   --password-store=gnome-libsecret
   ```
   For KWallet, add `--password-store=kwallet6` instead.
3. Restart Obsidian.

If you use Obsidian as a Flatpak or AppImage, add the same flag to the command line.

**Apple does not accept the sign-in.**

1. Open icloud.com in a private browser window.
2. Sign in there to make sure that the password is correct.
3. Do not try again many times. Apple locks an Apple ID after some failures. To unlock it, go to
   [iforgot.apple.com](https://iforgot.apple.com).

**The iCloud Drive web service is not available.**

1. Sign in at icloud.com one time.
2. Make sure that Advanced Data Protection is off.
3. Make sure that Access iCloud Data on the Web is on.

**All connections stop.** Some networks show IPv6 but do not send IPv6 data. Turn on Use IPv4 only.

## Build from source

```
npm ci
npm test          # 109 tests, run as TypeScript (Node 23.6 or newer)
npm run build     # makes main.js
npm run package   # makes dist/icloud-drive-sync-<version>.zip
```

`PLAN.md` contains the design decisions and the tests against iCloud.

## License

MIT. Refer to [LICENSE](LICENSE). The iCloud client (`src/icloud/`) is a TypeScript port of code from
pyicloud. The pyicloud MIT license is in [LICENSE.pyicloud](LICENSE.pyicloud).

## Disclaimer of liability

This plugin is free software. It is supplied "as is", without warranty of any kind, express or
implied. The [MIT license](LICENSE) gives the full terms.

**You use this plugin at your own risk. The use of this plugin is your responsibility, not the
responsibility of the author.**

The author is not liable for any loss or damage that comes from the use of this plugin, or from an
inability to use it. This includes, but is not limited to:

- loss, damage or corruption of notes, attachments, settings or other data;
- loss of data in iCloud Drive or on any device;
- a locked or disabled Apple ID;
- any direct, indirect, incidental or consequential damage.

If you do not agree to these conditions, do not install or use this plugin.
