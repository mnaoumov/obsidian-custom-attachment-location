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
  type AllowSyncFileFunction = (this: unknown, path: string, isFolder: boolean) => unknown;
  type GetRemoteVaultIdFunction = (this: unknown) => unknown;

  const instance = app.internalPlugins.getEnabledPluginById(InternalPluginName.Sync);
  if (!instance) {
    return { doesCarryFile: (): undefined => undefined, state: ObsidianSyncState.Off };
  }

  // TODO: Call instance.getRemoteVaultId() and instance.filter.allowSyncFile() directly once obsidian-typings declares them on SyncPluginInstance.
  const getRemoteVaultId = Reflect.get(instance, 'getRemoteVaultId') as GetRemoteVaultIdFunction | undefined;
  const remoteVaultId = typeof getRemoteVaultId === 'function' ? getRemoteVaultId.call(instance) : undefined;
  if (typeof remoteVaultId !== 'string' || remoteVaultId === '') {
    return { doesCarryFile: (): undefined => undefined, state: ObsidianSyncState.NotConnected };
  }

  const filter: unknown = Reflect.get(instance, 'filter');
  const allowSyncFile = typeof filter === 'object' && filter !== null ? Reflect.get(filter, 'allowSyncFile') as AllowSyncFileFunction | undefined : undefined;
  return {
    doesCarryFile: (path: string): boolean | undefined => {
      if (typeof allowSyncFile !== 'function') {
        return undefined;
      }
      const result = allowSyncFile.call(filter, path, false);
      return typeof result === 'boolean' ? result : undefined;
    },
    state: ObsidianSyncState.Connected
  };
}
