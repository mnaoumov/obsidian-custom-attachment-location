/**
 * @file
 *
 * Reads back the settings this plugin handed to Advanced Rename and Delete Handler in 12.0.0.
 *
 * Handing the rename/delete HANDLER over did not stop this plugin needing the VALUES. Collect attachments
 * cleans up folders it empties, Go to owning note ranks the notes referencing an attachment, `isNoteEx`
 * decides what counts as a note, and every command checks whether a path is ignored — none of which is a
 * rename or a delete. Rather than keep private copies of settings another plugin now owns, this plugin asks
 * for them.
 *
 * Reads are synchronous and uncached. `PluginApiRef.value` is maintained by the registry, so reading it is a
 * field access rather than a lookup, and asking on every call means there is no staleness to invalidate when
 * the user edits a setting in the other plugin's tab. Uncached also sidesteps the revoked-handle trap: the
 * handle is never stored, so a provider that unloads simply makes the next read fall back.
 */

import type { App } from 'obsidian';
import type { PluginApiRef } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import { ComponentEx } from 'obsidian-dev-utils/obsidian/components/component-ex';
import { watchPluginApi } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import type {
  AdvancedRenameAndDeleteHandlerApi,
  HandedOverSettings
} from './advanced-rename-and-delete-handler.ts';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE,
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
  ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT,
  DEFAULT_HANDED_OVER_SETTINGS
} from './advanced-rename-and-delete-handler.ts';

interface HandedOverSettingsComponentConstructorParams {
  readonly app: App;
}

export class HandedOverSettingsComponent extends ComponentEx {
  /**
   * The handed-over values, or this plugin's own defaults while the other plugin is unavailable.
   */
  public get settings(): HandedOverSettings {
    return this.apiRef?.value?.getSettings() ?? DEFAULT_HANDED_OVER_SETTINGS;
  }

  private apiRef: null | PluginApiRef<AdvancedRenameAndDeleteHandlerApi> = null;

  private readonly app: App;

  public constructor(params: HandedOverSettingsComponentConstructorParams) {
    super();
    this.app = params.app;
  }

  /**
   * Whether a path is one the handler leaves alone entirely.
   *
   * @param path - The vault-relative path.
   * @returns Whether the path is ignored. `false` while the other plugin is unavailable — nothing is
   * configured, so nothing is excluded.
   */
  public isPathIgnored(path: string): boolean {
    return this.apiRef?.value?.isPathIgnored(path) ?? false;
  }

  /**
   * Whether a file is an attachment even though its extension says otherwise.
   *
   * @param path - The vault-relative path.
   * @returns Whether the file is treated as an attachment.
   */
  public isTreatedAsAttachment(path: string): boolean {
    const api = this.apiRef?.value;
    if (api) {
      return api.isTreatedAsAttachment(path);
    }

    return DEFAULT_HANDED_OVER_SETTINGS.treatAsAttachmentExtensions.some((extension) => path.endsWith(extension));
  }

  public override onload(): void {
    // A watch rather than `whenAvailable()`: that wait blocks for ten seconds and then throws when the
    // Plugin is simply not installed, which would stall this plugin's load for every user who declined the
    // Suggestion. The ref costs nothing while the provider is absent and becomes live the moment it appears.
    this.apiRef = watchPluginApi<AdvancedRenameAndDeleteHandlerApi>({
      apiVersionRange: ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE,
      app: this.app,
      component: this,
      contract: ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT,
      pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID
    });
  }
}
