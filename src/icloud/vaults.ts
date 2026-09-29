/**
 * Finding Obsidian vaults in iCloud Drive: any folder holding a `.obsidian`
 * folder, at the Drive root or inside Obsidian's own iCloud container (which
 * is where the iPhone app keeps them, as an app_library). Port of obsisync's
 * discover_vaults.
 */
import { DriveClient, isFolderLike, type DriveItem } from "./drive.ts";

async function hasObsidianFolder(drive: DriveClient, folder: DriveItem): Promise<boolean> {
  try {
    return (await drive.list(folder)).some((c) => c.name === ".obsidian" && isFolderLike(c));
  } catch {
    return false;
  }
}

/** Vault paths like "Obsidian/My Vault", found in parallel. */
export async function discoverVaults(drive: DriveClient): Promise<string[]> {
  const root = await drive.root();
  const top = (await drive.list(root)).filter(isFolderLike);
  const found: string[] = [];
  await Promise.all(
    top.map(async (folder) => {
      if (await hasObsidianFolder(drive, folder)) found.push(folder.name);
      if (folder.type === "app_library" || folder.name === "Obsidian") {
        const inner = (await drive.list(folder).catch(() => [])).filter(isFolderLike);
        await Promise.all(
          inner.map(async (v) => {
            if (await hasObsidianFolder(drive, v)) found.push(`${folder.name}/${v.name}`);
          }),
        );
      }
    }),
  );
  return found.sort();
}
