import { Notice, Plugin } from "obsidian";

/**
 * Placeholder until phase 3. The iCloud client in src/icloud is exercised by
 * the tests and by spike/cli.ts; nothing here touches the network yet.
 */
export default class ICloudDriveSyncPlugin extends Plugin {
  override async onload(): Promise<void> {
    this.addCommand({
      id: "about",
      name: "About iCloud Drive Sync",
      callback: () => new Notice("iCloud Drive Sync is in development; sync is not enabled yet."),
    });
  }
}
