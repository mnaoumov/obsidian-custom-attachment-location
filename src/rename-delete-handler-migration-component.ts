/**
 * @file
 *
 * Offers the rename/delete values this plugin held before 12.0.0 to Advanced Rename and Delete Handler,
 * once, through that plugin's public API.
 *
 * This plugin never writes into another plugin's `data.json`. It PROPOSES; the other plugin owns the
 * settings, so it owns the dialog, and the user approves, edits or declines. Only an applied migration
 * retires the pending values.
 */

import type { App } from 'obsidian';
import type { PluginApiRef } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import { invokeAsyncSafely } from 'obsidian-dev-utils/async';
import { registerAsyncEvent } from 'obsidian-dev-utils/obsidian/components/async-events-component';
import { ComponentEx } from 'obsidian-dev-utils/obsidian/components/component-ex';
import { watchPluginApi } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import type { AdvancedRenameAndDeleteHandlerApi } from './advanced-rename-and-delete-handler.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE,
  ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT,
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID
} from './advanced-rename-and-delete-handler.ts';

interface RenameDeleteHandlerMigrationComponentConstructorParams {
  readonly app: App;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly sourcePluginId: string;
}

export class RenameDeleteHandlerMigrationComponent extends ComponentEx {
  private apiRef: null | PluginApiRef<AdvancedRenameAndDeleteHandlerApi> = null;

  private readonly app: App;

  private isProposing = false;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly sourcePluginId: string;

  public constructor(params: RenameDeleteHandlerMigrationComponentConstructorParams) {
    super();
    this.app = params.app;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.sourcePluginId = params.sourcePluginId;
  }

  public override onload(): void {
    // Nothing is gated on the pending value HERE. The settings component is a sibling whose own load is
    // Still in flight at this point, so its `settings` still holds the DEFAULTS — reading the pending value
    // Now would see `null` on exactly the vaults that have one, register no watch, and lose the migration
    // Permanently. Both edges are wired instead, and `propose` re-reads the value each time it runs.
    const ref = watchPluginApi<AdvancedRenameAndDeleteHandlerApi>({
      apiVersionRange: ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE,
      app: this.app,
      component: this,
      // Deliberately NARROWER than the read-back's contract: migrating needs only `migrateSettings`, which
      // Has been published since contract `1.0.0`. Asking for more here would refuse to offer the migration
      // To a user on an older provider — which is exactly the user who has settings to migrate.
      contract: ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT,
      pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID
    });

    // Driven by the ref's own event rather than by `whenAvailable()`, deliberately. That wait blocks for ten
    // Seconds and then throws when the plugin is simply not installed, which would stall this plugin's load
    // For every user who declines the suggestion. Watching costs nothing while the plugin is absent and
    // Offers the migration the moment it appears — including right after the user installs it from the
    // Suggestion banner.
    this.apiRef = ref;
    ref.on('change', this.handleApiChange);
    this.register(() => {
      ref.off('change', this.handleApiChange);
    });

    // The two edges that can make an offer possible, in either order: the provider appearing, and this
    // Plugin's own settings arriving from disk.
    registerAsyncEvent(this, this.pluginSettingsComponent.on('loadSettings', this.handleApiChange));
    this.handleApiChange();
  }

  // A stable identity, so the same function can be handed to both `on` and `off`.
  private readonly handleApiChange = (): void => {
    invokeAsyncSafely(() => this.propose(this.apiRef?.value ?? null));
  };

  private async propose(api: AdvancedRenameAndDeleteHandlerApi | null): Promise<void> {
    const proposedSettings = this.pluginSettingsComponent.settings.proposedRenameDeleteSettings;
    if (!api || this.isProposing || proposedSettings === null) {
      return;
    }

    this.isProposing = true;
    try {
      const result = await api.migrateSettings({
        proposedSettings,
        sourcePluginId: this.sourcePluginId
      });

      // A cancel is not an answer, so the values stay pending and the offer comes back — on the next load,
      // Or as soon as the provider reloads. Only an applied migration retires them.
      //
      // `editAndSave`, not `setProperty`: the latter only edits the in-memory state, so the retirement would
      // Be forgotten on the next reload and the migration would be offered again forever.
      if (result.isApplied) {
        await this.pluginSettingsComponent.editAndSave((settings) => {
          settings.proposedRenameDeleteSettings = null;
        });
      }
    } finally {
      this.isProposing = false;
    }
  }
}
