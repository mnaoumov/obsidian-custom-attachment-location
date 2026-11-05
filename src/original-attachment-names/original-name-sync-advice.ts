/**
 * @file
 *
 * Decides when synchronizing original attachment names between devices is worth it.
 *
 * It pays off only when two things are true at once: something carries the vault to other devices, and a template
 * reads `{{originalAttachmentFileName}}`, so another device would otherwise compute a different name. Obsidian Sync
 * is the one carrier the plugin can see. Git, Syncthing, iCloud and the like are invisible to it, so a user on one of
 * them is told when to turn synchronization on by hand rather than steered away from it.
 */

import type { ReadonlyDeep } from 'type-fest';

import type { PluginSettings } from '../settings/plugin-settings.ts';

import { ObsidianSyncState } from './obsidian-sync-status.ts';

const ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN = 'originalAttachmentFileName';

/**
 * What to tell the user about synchronizing original names on this device.
 */
export enum OriginalNameSyncAdvice {
  /**
   * Synchronization is on, through Obsidian Sync, but Obsidian Sync is not connected on this device any more.
   */
  EnabledWithoutObsidianSync = 'EnabledWithoutObsidianSync',

  /**
   * Synchronization is on and nothing contradicts it.
   */
  None = 'None',

  /**
   * Obsidian Sync is connected, but no template reads the original name, so synchronizing it buys nothing yet.
   */
  NotNeeded = 'NotNeeded',

  /**
   * Obsidian Sync is not connected. Only another sync tool would make synchronization useful.
   */
  ObsidianSyncNotConnected = 'ObsidianSyncNotConnected',

  /**
   * Obsidian Sync is connected and a template reads the original name: turn synchronization on.
   */
  Recommended = 'Recommended'
}

/**
 * Parameters for {@link getOriginalNameSyncAdvice}.
 */
export interface GetOriginalNameSyncAdviceParams {
  /**
   * Whether any setting reads the original name.
   */
  readonly doesTemplateReadOriginalName: boolean;

  /**
   * Whether this device's synchronization was set up for Obsidian Sync.
   */
  readonly isObsidianSyncProvider: boolean;

  /**
   * Whether this device synchronizes original names.
   */
  readonly isSyncEnabled: boolean;

  /**
   * How Obsidian Sync stands on this device.
   */
  readonly obsidianSyncState: ObsidianSyncState;
}

/**
 * Whether any setting reads the original attachment name.
 *
 * Every string setting is searched, custom token code included, because a token can be used in any template and a
 * custom token can read the name from its context. A false positive only shows advice; it never turns anything on.
 *
 * @param settings - The plugin settings.
 * @returns Whether a setting mentions the token.
 */
export function doesAnySettingReadOriginalAttachmentFileName(settings: ReadonlyDeep<PluginSettings>): boolean {
  return Object.values(settings).some((value) => typeof value === 'string' && value.includes(ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN));
}

/**
 * Picks the advice for this device.
 *
 * @param params - What is known about this device.
 * @returns The advice.
 */
export function getOriginalNameSyncAdvice(params: GetOriginalNameSyncAdviceParams): OriginalNameSyncAdvice {
  const isObsidianSyncConnected = params.obsidianSyncState === ObsidianSyncState.Connected;
  if (params.isSyncEnabled) {
    return params.isObsidianSyncProvider && !isObsidianSyncConnected ? OriginalNameSyncAdvice.EnabledWithoutObsidianSync : OriginalNameSyncAdvice.None;
  }

  if (!isObsidianSyncConnected) {
    return OriginalNameSyncAdvice.ObsidianSyncNotConnected;
  }

  return params.doesTemplateReadOriginalName ? OriginalNameSyncAdvice.Recommended : OriginalNameSyncAdvice.NotNeeded;
}
