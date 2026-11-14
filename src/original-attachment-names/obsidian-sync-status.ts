/**
 * @file
 *
 * Reads what the core Obsidian Sync plugin says about THIS device: whether it is on, whether it is connected to a
 * remote vault, and whether its selective-sync filter would carry a file.
 *
 * Only this device can be asked. Every other device has its own Sync settings, so a good answer here is never proof
 * that another device is ready.
 */

import type { App } from 'obsidian';

import { InternalPluginName } from '@obsidian-typings/obsidian-public-latest/implementations';

/**
 * How Obsidian Sync stands on this device.
 */
export enum ObsidianSyncState {
  /**
   * The core plugin is on and connected to a remote vault.
   */
  Connected = 'Connected',

  /**
   * The core plugin is on, but no remote vault is connected.
   */
  NotConnected = 'NotConnected',

  /**
   * The core plugin is off.
   */
  Off = 'Off'
}

/**
 * What Obsidian Sync says about this device.
 */
export interface ObsidianSyncStatus {
  /**
   * Whether Obsidian Sync would carry a file at a path, by its own selective-sync settings: the file type (JSON needs
   * `Sync all other types`) and its excluded folders.
   *
   * @param path - A vault-relative file path.
   * @returns `true` or `false` when connected, `undefined` when there is nothing to ask.
   */
  readonly doesCarryFile: (this: void, path: string) => boolean | undefined;

  /**
   * How Obsidian Sync stands.
   */
  readonly state: ObsidianSyncState;
}

/**
 * Asks the core Sync plugin how it stands on this device.
 *
 * @param app - The app.
 * @returns The status.
 */
export function getObsidianSyncStatus(app: App): ObsidianSyncStatus {
  const instance = app.internalPlugins.getEnabledPluginById(InternalPluginName.Sync);
  if (!instance) {
    return { doesCarryFile: (): undefined => undefined, state: ObsidianSyncState.Off };
  }

  if (!instance.getRemoteVaultId()) {
    return { doesCarryFile: (): undefined => undefined, state: ObsidianSyncState.NotConnected };
  }

  return {
    doesCarryFile: (path: string): boolean => instance.filter.allowSyncFile(path, false),
    state: ObsidianSyncState.Connected
  };
}
